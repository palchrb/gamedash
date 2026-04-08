/**
 * Audit log — append-only JSONL file with in-process size-based rotation.
 *
 * One event per line, each event carries `at` (ISO timestamp) + `kind`
 * (string) + arbitrary payload. We rotate internally so an out-of-the-
 * box install has bounded disk usage without relying on logrotate on
 * the host. Rotation is size-triggered: when `audit.log` exceeds
 * AUDIT_LOG_MAX_BYTES the file is renamed `audit.log.1`, existing
 * `.N` files are bumped up, and anything past `AUDIT_LOG_MAX_FILES` is
 * deleted. Rotation runs in the periodic sweep in server.ts; the hot
 * path (`audit()`) stays a single append.
 */

import { promises as fs } from "node:fs";
import { config } from "../config";
import { appendJsonLine } from "../lib/atomic-file";
import { logger } from "../logger";

export type AuditEvent = Record<string, unknown> & { kind: string };

const DEFAULT_MAX_BYTES = 10 * 1024 * 1024; // 10 MB
const DEFAULT_MAX_FILES = 5;

export async function audit(event: AuditEvent): Promise<void> {
  try {
    await appendJsonLine(config().auditLog, {
      at: new Date().toISOString(),
      ...event,
    });
  } catch (err) {
    // Never let audit failure break the request. Log loudly instead.
    logger().error({ err: (err as Error).message, event }, "audit write failed");
  }
}

/**
 * Rotate the audit log if it exceeds `maxBytes`. Called from the
 * periodic sweep in server.ts — safe to call frequently since it is
 * a single `stat` when no rotation is needed.
 */
export async function rotateAuditLogIfNeeded(params?: {
  maxBytes?: number;
  maxFiles?: number;
}): Promise<boolean> {
  const maxBytes = params?.maxBytes ?? DEFAULT_MAX_BYTES;
  const maxFiles = params?.maxFiles ?? DEFAULT_MAX_FILES;
  const base = config().auditLog;
  let size = 0;
  try {
    const stat = await fs.stat(base);
    size = stat.size;
  } catch (err) {
    // Missing file is fine — nothing to rotate.
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return false;
    logger().warn(
      { err: (err as Error).message, file: base },
      "audit rotate: stat failed",
    );
    return false;
  }
  if (size <= maxBytes) return false;

  // Drop the oldest file if it exists.
  const oldest = `${base}.${maxFiles}`;
  try {
    await fs.unlink(oldest);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
      logger().warn(
        { err: (err as Error).message, file: oldest },
        "audit rotate: unlink oldest failed",
      );
    }
  }

  // Shift `.N` → `.N+1` from highest to lowest.
  for (let i = maxFiles - 1; i >= 1; i--) {
    const from = `${base}.${i}`;
    const to = `${base}.${i + 1}`;
    try {
      await fs.rename(from, to);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
        logger().warn(
          { err: (err as Error).message, from, to },
          "audit rotate: shift failed",
        );
      }
    }
  }

  // Finally, rename the live log to `.1` and let the next append create a fresh file.
  try {
    await fs.rename(base, `${base}.1`);
    logger().info({ rotated: base, sizeBytes: size }, "audit log rotated");
    return true;
  } catch (err) {
    logger().warn(
      { err: (err as Error).message, file: base },
      "audit rotate: final rename failed",
    );
    return false;
  }
}
