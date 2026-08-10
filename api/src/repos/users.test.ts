/**
 * Tests for the users repo — focused on the tokenHash→tokens[] migration
 * and the share-code mint/claim lifecycle.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { resetConfigForTests } from "../config";
import { resetLoggerForTests } from "../logger";
import { sha256Hex } from "../lib/hash";
import { normalizeShareCode } from "../lib/hash";
import {
  anyClaimCodeOutstanding,
  claimShareCode,
  createUser,
  findByToken,
  findUserByClaimCode,
  loadUsers,
  mintClaimCode,
  revokeUserToken,
  rotateToken,
  suspendUser,
} from "./users";

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gamedash-users-"));
  process.env["DATA_DIR"] = tmpDir;
  process.env["LOG_LEVEL"] = "silent";
  resetConfigForTests();
  resetLoggerForTests();
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
  delete process.env["DATA_DIR"];
  delete process.env["LOG_LEVEL"];
});

describe("tokenHash → tokens[] migration", () => {
  it("lifts a legacy scalar tokenHash into the tokens array on load", async () => {
    const legacy = {
      users: [
        {
          id: "u_old",
          name: "OldKid",
          tokenHash: "deadbeef".repeat(8),
          allowedServices: ["mc1"],
          locale: null,
          createdAt: "2025-01-01T00:00:00.000Z",
          history: [],
          credentials: [],
          registrationOpenUntil: null,
          suspended: false,
        },
      ],
    };
    fs.writeFileSync(path.join(tmpDir, "users.json"), JSON.stringify(legacy));

    const data = await loadUsers();
    const u = data.users[0]!;
    expect(u.tokens).toHaveLength(1);
    expect(u.tokens[0]!.hash).toBe("deadbeef".repeat(8));
    expect(u.tokens[0]!.createdAt).toBe("2025-01-01T00:00:00.000Z");
    expect(u.claimCode).toBeNull();
  });

  it("findByToken matches any token in the list", async () => {
    const { plainToken, user } = await createUser({
      name: "Kid",
      allowedServices: [],
      locale: null,
    });
    expect((await findByToken(plainToken))?.id).toBe(user.id);
    expect(await findByToken("wrong-token")).toBeNull();
  });
});

describe("share codes", () => {
  it("mint → claim issues a fresh token without killing the old one", async () => {
    const { plainToken: original, user } = await createUser({
      name: "Kid",
      allowedServices: [],
      locale: null,
    });
    const { code } = await mintClaimCode(user.id);
    expect(await anyClaimCodeOutstanding()).toBe(true);

    const normalized = normalizeShareCode(code);
    expect(normalized).toBe(code);

    const claimed = await claimShareCode(normalized!);
    expect(claimed).not.toBeNull();
    expect(claimed!.user.id).toBe(user.id);

    // Both tokens now valid
    expect((await findByToken(original))?.id).toBe(user.id);
    expect((await findByToken(claimed!.plainToken))?.id).toBe(user.id);

    // Code is single-use
    expect(await claimShareCode(normalized!)).toBeNull();
    expect(await anyClaimCodeOutstanding()).toBe(false);
  });

  it("expired codes match nothing and are consumed", async () => {
    const { user } = await createUser({ name: "Kid", allowedServices: [], locale: null });
    const { code } = await mintClaimCode(user.id);
    // Force-expire by rewriting the stored expiry
    const file = path.join(tmpDir, "users.json");
    const raw = JSON.parse(fs.readFileSync(file, "utf8"));
    raw.users[0].claimCode.expiresAt = new Date(Date.now() - 1000).toISOString();
    fs.writeFileSync(file, JSON.stringify(raw));

    expect(await anyClaimCodeOutstanding()).toBe(false);
    expect(await findUserByClaimCode(code)).toBeNull();
    expect(await claimShareCode(code)).toBeNull();
    // Consumed on the failed attempt
    const after = await loadUsers();
    expect(after.users[0]!.claimCode).toBeNull();
  });

  it("refuses to mint for suspended users, and claim fails if suspended after mint", async () => {
    const { user } = await createUser({ name: "Kid", allowedServices: [], locale: null });
    const { code } = await mintClaimCode(user.id);
    await suspendUser(user.id);
    expect(await claimShareCode(code)).toBeNull();
    await expect(mintClaimCode(user.id)).rejects.toThrow(/suspended/u);
  });

  it("rotateToken kills all tokens and any outstanding code", async () => {
    const { plainToken: original, user } = await createUser({
      name: "Kid",
      allowedServices: [],
      locale: null,
    });
    const { code } = await mintClaimCode(user.id);
    const claimed = await claimShareCode(normalizeShareCode(code)!);
    await mintClaimCode(user.id); // fresh outstanding code

    const fresh = await rotateToken(user.id);
    expect(await findByToken(original)).toBeNull();
    expect(await findByToken(claimed!.plainToken)).toBeNull();
    expect((await findByToken(fresh))?.id).toBe(user.id);
    expect(await anyClaimCodeOutstanding()).toBe(false);
  });

  it("revokeUserToken removes one token but never the last", async () => {
    const { plainToken: original, user } = await createUser({
      name: "Kid",
      allowedServices: [],
      locale: null,
    });
    const { code } = await mintClaimCode(user.id);
    const claimed = await claimShareCode(normalizeShareCode(code)!);

    const removed = await revokeUserToken(user.id, sha256Hex(claimed!.plainToken));
    expect(removed).toBe(true);
    expect(await findByToken(claimed!.plainToken)).toBeNull();
    expect((await findByToken(original))?.id).toBe(user.id);

    await expect(revokeUserToken(user.id, sha256Hex(original))).rejects.toThrow(/last/u);
  });
});

describe("normalizeShareCode", () => {
  it("accepts dashes, spaces, lowercase", () => {
    expect(normalizeShareCode("abcd-efgh".toUpperCase())).toBe("ABCDEFGH");
    expect(normalizeShareCode(" ab cd-ef gh ")).toBe("ABCDEFGH");
  });
  it("rejects wrong length and out-of-alphabet characters", () => {
    expect(normalizeShareCode("ABC")).toBeNull();
    expect(normalizeShareCode("ABCDEFG0")).toBeNull(); // 0 not in alphabet
    expect(normalizeShareCode("ABCDEFGI")).toBeNull(); // I not in alphabet
    expect(normalizeShareCode("ABCDEFGU")).toBeNull(); // U not in alphabet
  });
});
