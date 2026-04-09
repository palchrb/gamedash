/**
 * Atomic JSON file repository with in-process mutex and Zod validation.
 *
 * Why atomic:
 *   A crashed or concurrent write to a JSON file can leave the file
 *   truncated or with interleaved content. We write to a sibling `.tmp`
 *   file, fsync it, then rename() — which is atomic on POSIX filesystems.
 *
 * Why mutex:
 *   Node is single-threaded, but async writes can still interleave if two
 *   requests both call `load → mutate → save`. A per-file mutex serialises
 *   mutations so a read-modify-write never sees a torn state.
 *
 * Why Zod on load:
 *   If the file is corrupt or hand-edited wrong, we want to CRASH LOUDLY
 *   at load time instead of half-silently losing data mid-operation. The
 *   only exception is "file does not exist", where we return a default.
 */

import { promises as fs, constants as fsConstants } from "node:fs";
import * as path from "node:path";
import type { z } from "zod";

// ── Per-path mutex ─────────────────────────────────────────────────────

type Waiter = () => void;
const chains = new Map<string, { promise: Promise<void>; depth: number }>();

function acquire(key: string): Promise<Waiter> {
  let release!: Waiter;
  const next = new Promise<void>((resolve) => {
    release = resolve;
  });
  const entry = chains.get(key);
  const prev = entry?.promise ?? Promise.resolve();
  const depth = (entry?.depth ?? 0) + 1;
  chains.set(key, { promise: prev.then(() => next), depth });
  return prev.then(() => release);
}

/** Run `fn` with exclusive access to `key`. */
export async function withLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const release = await acquire(key);
  try {
    return await fn();
  } finally {
    release();
    const entry = chains.get(key);
    if (entry) {
      entry.depth--;
      if (entry.depth <= 0) chains.delete(key);
    }
  }
}

// ── Atomic read/write ──────────────────────────────────────────────────

/** Write `data` atomically: temp file + fsync + rename. */
export async function writeAtomic(filePath: string, data: string): Promise<void> {
  const dir = path.dirname(filePath);
  await fs.mkdir(dir, { recursive: true });
  const tmp = `${filePath}.${process.pid}.${Date.now()}.tmp`;
  const fh = await fs.open(tmp, "w", 0o600);
  try {
    await fh.writeFile(data, "utf8");
    await fh.sync();
  } finally {
    await fh.close();
  }
  await fs.rename(tmp, filePath);
}

/**
 * Read a JSON file and parse through a schema. Returns `defaultValue` if the
 * file does not exist. Uses z.output<S> so schemas with `.default()` are
 * handled correctly (input optional, output required).
 */
export async function readJson<S extends z.ZodTypeAny>(
  filePath: string,
  schema: S,
  defaultValue: z.output<S>,
): Promise<z.output<S>> {
  let raw: string;
  try {
    raw = await fs.readFile(filePath, "utf8");
  } catch (err: unknown) {
    if (isNodeError(err) && err.code === "ENOENT") return defaultValue;
    throw err;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Failed to parse ${filePath}: ${(err as Error).message}`);
  }
  const result = schema.safeParse(parsed);
  if (!result.success) {
    const details = result.error.issues
      .map((i) => `  - ${i.path.join(".") || "(root)"}: ${i.message}`)
      .join("\n");
    throw new Error(`Corrupt or invalid ${filePath}:\n${details}`);
  }
  return result.data as z.output<S>;
}

/** Write a JSON-serialisable object after validating against a schema. */
export async function writeJson<S extends z.ZodTypeAny>(
  filePath: string,
  schema: S,
  data: z.output<S>,
): Promise<void> {
  const result = schema.safeParse(data);
  if (!result.success) {
    throw new Error(
      `Refusing to write invalid data to ${filePath}: ${result.error.message}`,
    );
  }
  await writeAtomic(filePath, JSON.stringify(result.data, null, 2));
}

/** Append a single JSON object as a JSONL line. Creates parent dirs as needed. */
export async function appendJsonLine(
  filePath: string,
  obj: Record<string, unknown>,
): Promise<void> {
  const dir = path.dirname(filePath);
  await fs.mkdir(dir, { recursive: true });
  const line = `${JSON.stringify(obj)}\n`;
  await fs.appendFile(filePath, line, { mode: 0o600 });
}

/** Check whether a path exists (any type). */
export async function pathExists(filePath: string): Promise<boolean> {
  try {
    await fs.access(filePath, fsConstants.F_OK);
    return true;
  } catch {
    return false;
  }
}

interface NodeSystemError extends Error {
  code?: string;
}

function isNodeError(err: unknown): err is NodeSystemError {
  return err instanceof Error && typeof (err as NodeSystemError).code === "string";
}
