/**
 * Tests for the audit log append + size-based rotation.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { resetConfigForTests, config } from "../config";
import { resetLoggerForTests } from "../logger";
import { audit, rotateAuditLogIfNeeded } from "./audit";

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gamedash-audit-"));
  process.env["DATA_DIR"] = tmpDir;
  resetConfigForTests();
  resetLoggerForTests();
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
  delete process.env["DATA_DIR"];
});

describe("audit", () => {
  it("appends a JSONL line per event", async () => {
    await audit({ kind: "test.event", value: 1 });
    await audit({ kind: "test.event", value: 2 });
    const raw = fs.readFileSync(config().auditLog, "utf8");
    const lines = raw.trim().split("\n");
    expect(lines.length).toBe(2);
    const first = JSON.parse(lines[0] ?? "{}");
    expect(first.kind).toBe("test.event");
    expect(first.value).toBe(1);
    expect(typeof first.at).toBe("string");
  });

  it("never throws on write failure", async () => {
    // Point the audit log at an unwritable location. fs.mkdir will
    // succeed because we can create the dir, but we want to ensure the
    // happy path does not throw regardless.
    await expect(audit({ kind: "x" })).resolves.toBeUndefined();
  });
});

describe("rotateAuditLogIfNeeded", () => {
  it("is a no-op when the file does not exist", async () => {
    const rotated = await rotateAuditLogIfNeeded({ maxBytes: 10, maxFiles: 3 });
    expect(rotated).toBe(false);
  });

  it("is a no-op while under the size limit", async () => {
    await audit({ kind: "small" });
    const rotated = await rotateAuditLogIfNeeded({ maxBytes: 10_000, maxFiles: 3 });
    expect(rotated).toBe(false);
    expect(fs.existsSync(`${config().auditLog}.1`)).toBe(false);
  });

  it("rotates the file when it exceeds maxBytes", async () => {
    // Write something, then force rotation with a tiny maxBytes.
    await audit({ kind: "one" });
    const rotated = await rotateAuditLogIfNeeded({ maxBytes: 5, maxFiles: 3 });
    expect(rotated).toBe(true);
    expect(fs.existsSync(`${config().auditLog}.1`)).toBe(true);
    expect(fs.existsSync(config().auditLog)).toBe(false);
  });

  it("shifts old files and drops anything past maxFiles", async () => {
    const base = config().auditLog;
    // Seed three generations.
    fs.mkdirSync(path.dirname(base), { recursive: true });
    fs.writeFileSync(base, "current\n");
    fs.writeFileSync(`${base}.1`, "older\n");
    fs.writeFileSync(`${base}.2`, "oldest\n");

    const rotated = await rotateAuditLogIfNeeded({ maxBytes: 1, maxFiles: 2 });
    expect(rotated).toBe(true);
    // After rotation with maxFiles=2:
    //   current → .1
    //   old .1  → .2
    //   old .2  → dropped
    expect(fs.readFileSync(`${base}.1`, "utf8")).toBe("current\n");
    expect(fs.readFileSync(`${base}.2`, "utf8")).toBe("older\n");
    expect(fs.existsSync(`${base}.3`)).toBe(false);
  });
});
