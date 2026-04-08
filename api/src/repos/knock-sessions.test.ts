/**
 * Tests for the knock session repo + TTL bookkeeping.
 *
 * Mirrors the admin sessions test: create, lookup, sweep expired,
 * and delete-for-user. Cookie round-trip is covered separately.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { resetConfigForTests } from "../config";
import { resetLoggerForTests } from "../logger";
import {
  addKnockSession,
  deleteKnockSessionsForUser,
  findKnockSessionByIdHash,
  hashKnockSessionId,
  sweepExpiredKnockSessions,
} from "./knock-sessions";
import type { KnockSession } from "../schemas";

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gamedash-knock-sessions-"));
  process.env["DATA_DIR"] = tmpDir;
  resetConfigForTests();
  resetLoggerForTests();
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
  delete process.env["DATA_DIR"];
});

function makeSession(
  overrides: Partial<KnockSession> & { idHash: string },
): KnockSession {
  const now = new Date().toISOString();
  return {
    userId: "u1",
    createdAt: now,
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    lastSeenAt: now,
    ip: "127.0.0.1",
    ua: "vitest",
    ...overrides,
  };
}

describe("knock sessions repo", () => {
  it("stores and looks up a session by its hash", async () => {
    const idHash = hashKnockSessionId("plain-knock-id");
    await addKnockSession(makeSession({ idHash }));
    const found = await findKnockSessionByIdHash(idHash);
    expect(found).not.toBeNull();
    expect(found?.userId).toBe("u1");
  });

  it("hashKnockSessionId is deterministic and distinct per input", () => {
    expect(hashKnockSessionId("abc")).toBe(hashKnockSessionId("abc"));
    expect(hashKnockSessionId("abc")).not.toBe(hashKnockSessionId("xyz"));
  });

  it("sweepExpiredKnockSessions removes only expired sessions", async () => {
    const alive = hashKnockSessionId("alive");
    const dead = hashKnockSessionId("dead");
    await addKnockSession(
      makeSession({
        idHash: alive,
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
      }),
    );
    await addKnockSession(
      makeSession({
        idHash: dead,
        expiresAt: new Date(Date.now() - 60_000).toISOString(),
      }),
    );
    const removed = await sweepExpiredKnockSessions();
    expect(removed).toBe(1);
    expect(await findKnockSessionByIdHash(alive)).not.toBeNull();
    expect(await findKnockSessionByIdHash(dead)).toBeNull();
  });

  it("deleteKnockSessionsForUser removes every session for that user", async () => {
    await addKnockSession(makeSession({ idHash: "h1", userId: "userA" }));
    await addKnockSession(makeSession({ idHash: "h2", userId: "userA" }));
    await addKnockSession(makeSession({ idHash: "h3", userId: "userB" }));

    const removed = await deleteKnockSessionsForUser("userA");
    expect(removed).toBe(2);
    expect(await findKnockSessionByIdHash("h1")).toBeNull();
    expect(await findKnockSessionByIdHash("h2")).toBeNull();
    expect(await findKnockSessionByIdHash("h3")).not.toBeNull();
  });
});
