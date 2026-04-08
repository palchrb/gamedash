/**
 * Tests for atomic JSON read/write + per-file mutex.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { z } from "zod";
import { readJson, withLock, writeAtomic, writeJson } from "./atomic-file";

const Schema = z.object({
  value: z.number().int(),
  items: z.array(z.string()).default([]),
});

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gamedash-test-"));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("writeAtomic", () => {
  it("writes a file atomically via temp + rename", async () => {
    const file = path.join(tmpDir, "a.json");
    await writeAtomic(file, "hello");
    expect(fs.readFileSync(file, "utf8")).toBe("hello");
  });

  it("creates missing parent directories", async () => {
    const file = path.join(tmpDir, "nested", "deep", "b.json");
    await writeAtomic(file, "data");
    expect(fs.existsSync(file)).toBe(true);
  });
});

describe("readJson / writeJson", () => {
  it("returns the default when the file does not exist", async () => {
    const file = path.join(tmpDir, "missing.json");
    const result = await readJson(file, Schema, { value: 0, items: [] });
    expect(result).toEqual({ value: 0, items: [] });
  });

  it("round-trips data through the schema", async () => {
    const file = path.join(tmpDir, "roundtrip.json");
    await writeJson(file, Schema, { value: 42, items: ["a", "b"] });
    const loaded = await readJson(file, Schema, { value: 0, items: [] });
    expect(loaded).toEqual({ value: 42, items: ["a", "b"] });
  });

  it("throws on corrupt JSON", async () => {
    const file = path.join(tmpDir, "corrupt.json");
    fs.writeFileSync(file, "{not valid json");
    await expect(readJson(file, Schema, { value: 0, items: [] })).rejects.toThrow(
      /Failed to parse/u,
    );
  });

  it("throws on schema mismatch", async () => {
    const file = path.join(tmpDir, "bad.json");
    fs.writeFileSync(file, JSON.stringify({ value: "not a number" }));
    await expect(readJson(file, Schema, { value: 0, items: [] })).rejects.toThrow(
      /Corrupt or invalid/u,
    );
  });

  it("refuses to write data that doesn't match the schema", async () => {
    const file = path.join(tmpDir, "bad-write.json");
    await expect(
      writeJson(file, Schema, { value: "wrong" as unknown as number, items: [] }),
    ).rejects.toThrow(/Refusing to write/u);
  });
});

describe("withLock", () => {
  it("serialises concurrent operations on the same key", async () => {
    const order: string[] = [];
    await Promise.all([
      withLock("shared", async () => {
        order.push("a-start");
        await new Promise((r) => setTimeout(r, 30));
        order.push("a-end");
      }),
      withLock("shared", async () => {
        order.push("b-start");
        await new Promise((r) => setTimeout(r, 10));
        order.push("b-end");
      }),
      withLock("shared", async () => {
        order.push("c-start");
        order.push("c-end");
      }),
    ]);
    expect(order).toEqual([
      "a-start",
      "a-end",
      "b-start",
      "b-end",
      "c-start",
      "c-end",
    ]);
  });

  it("isolates different keys", async () => {
    const events: string[] = [];
    await Promise.all([
      withLock("key-a", async () => {
        events.push("a1");
        await new Promise((r) => setTimeout(r, 20));
        events.push("a2");
      }),
      withLock("key-b", async () => {
        events.push("b1");
        await new Promise((r) => setTimeout(r, 5));
        events.push("b2");
      }),
    ]);
    // b1/b2 should complete before a2 because they run in parallel.
    expect(events.indexOf("b2")).toBeLessThan(events.indexOf("a2"));
  });
});
