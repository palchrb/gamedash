/**
 * Tests for the admin session repo + TTL/reauth bookkeeping.
 *
 * Covers what matters at the persistence layer:
 *   - create session, look up by hash
 *   - expired sessions are dropped by the sweep
 *   - hashSessionId is deterministic (so lookups work)
 * The full cookie round-trip through Express is covered by route-level
 * tests (TODO when we add supertest coverage).
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { resetConfigForTests } from "../config";
import { resetLoggerForTests } from "../logger";
import {
  addAdminSession,
  findAdminSessionByIdHash,
  hashSessionId,
  sweepExpiredSessions,
} from "../repos/admin";
import type { AdminSession } from "../schemas";

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gamedash-sessions-"));
  process.env["DATA_DIR"] = tmpDir;
  resetConfigForTests();
  resetLoggerForTests();
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
  delete process.env["DATA_DIR"];
});

function makeSession(
  overrides: Partial<AdminSession> & { idHash: string },
): AdminSession {
  const now = new Date().toISOString();
  return {
    adminId: "a1",
    createdAt: now,
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    reauthAfter: new Date(Date.now() + 7 * 24 * 3_600_000).toISOString(),
    lastSeenAt: now,
    ip: "127.0.0.1",
    ua: "vitest",
    ...overrides,
  };
}

describe("admin sessions repo", () => {
  it("stores and looks up a session by its hash", async () => {
    const idHash = hashSessionId("plain-session-id");
    await addAdminSession(makeSession({ idHash }));
    const found = await findAdminSessionByIdHash(idHash);
    expect(found).not.toBeNull();
    expect(found?.adminId).toBe("a1");
  });

  it("hashSessionId is deterministic", () => {
    expect(hashSessionId("abc")).toBe(hashSessionId("abc"));
    expect(hashSessionId("abc")).not.toBe(hashSessionId("xyz"));
  });

  it("sweepExpiredSessions removes only expired sessions", async () => {
    const alive = hashSessionId("alive");
    const dead = hashSessionId("dead");
    await addAdminSession(
      makeSession({
        idHash: alive,
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
      }),
    );
    await addAdminSession(
      makeSession({
        idHash: dead,
        expiresAt: new Date(Date.now() - 60_000).toISOString(),
      }),
    );
    const removed = await sweepExpiredSessions();
    expect(removed).toBe(1);
    expect(await findAdminSessionByIdHash(alive)).not.toBeNull();
    expect(await findAdminSessionByIdHash(dead)).toBeNull();
  });
});
