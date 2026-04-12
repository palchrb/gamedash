/**
 * Tests for the knock flow — atomic rule creation, renewal, IP swap, and
 * revoke. External side-effects (UFW, audit, user history) are mocked out;
 * the firewall-rules repo uses real file IO against a temp directory so we
 * can verify atomicity under concurrent access.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resetConfigForTests } from "../config";
import { resetLoggerForTests } from "../logger";

// Mock external side-effects so tests don't shell out to ufw / write audit.
vi.mock("../firewall/ufw", () => ({
  ufwAllowMany: vi.fn().mockResolvedValue([]),
  ufwDeleteMany: vi.fn().mockResolvedValue([]),
}));
vi.mock("../repos/audit", () => ({
  audit: vi.fn().mockResolvedValue(undefined),
}));
vi.mock("../repos/users", () => ({
  pushHistory: vi.fn().mockResolvedValue(undefined),
}));
vi.mock("../firewall/connections", () => ({
  isIpActiveOnPorts: vi.fn().mockResolvedValue({ active: false, matchCount: 0 }),
  isAnyIpActiveOnPorts: vi.fn().mockResolvedValue({ active: false, matchCount: 0 }),
}));

import { isAnyIpActiveOnPorts } from "../firewall/connections";
import { knockUser, revokeUser } from "./smart-revoke";
import { loadRules } from "../repos/firewall-rules";
import type { UserRecord } from "../schemas";
import type { Registry } from "../services/registry";

let tmpDir: string;

const fakeUser: UserRecord = {
  id: "u1",
  name: "TestKid",
  tokenHash: "abc123",
  allowedServices: ["mc1"],
  locale: null,
  createdAt: new Date().toISOString(),
  history: [],
  credentials: [],
  registrationOpenUntil: null,
  suspended: false,
};

const fakeRegistry = {
  collectPorts: () => [{ port: "25565", proto: "tcp" as const }],
  buildRuleServices: (ids: string[]) =>
    ids.map((id) => ({ id, ports: [{ port: "25565", proto: "tcp" as const }] })),
} as unknown as Registry;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gamedash-knock-"));
  process.env["DATA_DIR"] = tmpDir;
  process.env["LOG_LEVEL"] = "silent";
  resetConfigForTests();
  resetLoggerForTests();
  vi.mocked(isAnyIpActiveOnPorts).mockResolvedValue({ active: false, matchCount: 0 });
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
  delete process.env["DATA_DIR"];
  delete process.env["LOG_LEVEL"];
});

describe("knockUser", () => {
  it("creates a firewall rule for a new knock", async () => {
    const result = await knockUser(fakeUser, ["203.0.113.1"], "all", fakeRegistry, {
      skipAudit: true,
    });
    expect(result.status).toBe("ok");
    if (result.status !== "ok") throw new Error("unexpected");
    expect(result.rule.ips).toEqual(["203.0.113.1"]);
    expect(result.rule.userId).toBe("u1");

    const rules = await loadRules();
    expect(rules.rules).toHaveLength(1);
    expect(rules.rules[0]!.ips).toEqual(["203.0.113.1"]);
  });

  it("creates a dual-stack rule when both IPv4 and IPv6 are provided", async () => {
    const result = await knockUser(
      fakeUser,
      ["203.0.113.1", "2001:db8::1"],
      "all",
      fakeRegistry,
      { skipAudit: true },
    );
    expect(result.status).toBe("ok");
    if (result.status !== "ok") throw new Error("unexpected");
    expect(result.rule.ips).toEqual(["203.0.113.1", "2001:db8::1"]);

    const rules = await loadRules();
    expect(rules.rules).toHaveLength(1);
    expect(rules.rules[0]!.ips).toEqual(["203.0.113.1", "2001:db8::1"]);
  });

  it("renews on same IP without creating a duplicate rule", async () => {
    await knockUser(fakeUser, ["203.0.113.1"], "all", fakeRegistry, { skipAudit: true });
    const result = await knockUser(fakeUser, ["203.0.113.1"], "all", fakeRegistry, {
      skipAudit: true,
    });
    expect(result.status).toBe("ok");

    const rules = await loadRules();
    expect(rules.rules).toHaveLength(1);
  });

  it("merges a new IP into an existing rule on overlap (same network)", async () => {
    // First knock: only v4 is known
    await knockUser(fakeUser, ["203.0.113.1"], "all", fakeRegistry, { skipAudit: true });
    // Second knock: client re-detects with both v4 and v6 — the v4 overlaps
    // with the existing rule, so we merge in the v6 instead of swapping.
    const result = await knockUser(
      fakeUser,
      ["203.0.113.1", "2001:db8::1"],
      "all",
      fakeRegistry,
      { skipAudit: true },
    );
    expect(result.status).toBe("ok");
    if (result.status !== "ok") throw new Error("unexpected");
    expect(result.rule.ips).toEqual(["203.0.113.1", "2001:db8::1"]);

    const rules = await loadRules();
    expect(rules.rules).toHaveLength(1);
    expect(rules.rules[0]!.ips).toEqual(["203.0.113.1", "2001:db8::1"]);
  });

  it("swaps to new IP when no active session", async () => {
    await knockUser(fakeUser, ["203.0.113.1"], "all", fakeRegistry, { skipAudit: true });
    const result = await knockUser(fakeUser, ["203.0.113.2"], "all", fakeRegistry, {
      skipAudit: true,
    });
    expect(result.status).toBe("ok");
    if (result.status !== "ok") throw new Error("unexpected");
    expect(result.rule.ips).toEqual(["203.0.113.2"]);

    const rules = await loadRules();
    expect(rules.rules).toHaveLength(1);
    expect(rules.rules[0]!.ips).toEqual(["203.0.113.2"]);
  });

  it("returns requires_confirm when old IP has active session", async () => {
    await knockUser(fakeUser, ["203.0.113.1"], "all", fakeRegistry, { skipAudit: true });
    vi.mocked(isAnyIpActiveOnPorts).mockResolvedValueOnce({ active: true, matchCount: 2 });

    const result = await knockUser(fakeUser, ["203.0.113.2"], "all", fakeRegistry);
    expect(result.status).toBe("requires_confirm");
    if (result.status !== "requires_confirm") throw new Error("unexpected");
    expect(result.oldIps).toEqual(["203.0.113.1"]);
    expect(result.matchCount).toBe(2);

    // Rule should remain unchanged
    const rules = await loadRules();
    expect(rules.rules[0]!.ips).toEqual(["203.0.113.1"]);
  });

  it("swaps with force even when active session exists", async () => {
    await knockUser(fakeUser, ["203.0.113.1"], "all", fakeRegistry, { skipAudit: true });
    // force: true bypasses the isAnyIpActiveOnPorts check entirely, so we
    // don't set a mockResolvedValueOnce here (it would leak to the next test).
    const result = await knockUser(fakeUser, ["203.0.113.2"], "all", fakeRegistry, {
      force: true,
      skipAudit: true,
    });
    expect(result.status).toBe("ok");
    if (result.status !== "ok") throw new Error("unexpected");
    expect(result.rule.ips).toEqual(["203.0.113.2"]);
  });

  it("serialises concurrent knocks (no duplicate rules)", async () => {
    const [r1, r2] = await Promise.all([
      knockUser(fakeUser, ["203.0.113.1"], "all", fakeRegistry, { skipAudit: true }),
      knockUser(fakeUser, ["203.0.113.2"], "all", fakeRegistry, { skipAudit: true }),
    ]);
    expect(r1.status).toBe("ok");
    expect(r2.status).toBe("ok");

    // The lock ensures only one rule exists for the user, regardless of
    // which knock completed last.
    const rules = await loadRules();
    expect(rules.rules).toHaveLength(1);
  });
});

describe("revokeUser", () => {
  it("removes an existing rule", async () => {
    await knockUser(fakeUser, ["203.0.113.1"], "all", fakeRegistry, { skipAudit: true });
    const result = await revokeUser("u1");
    expect(result.removed).toBe(true);
    expect(result.ips).toEqual(["203.0.113.1"]);

    const rules = await loadRules();
    expect(rules.rules).toHaveLength(0);
  });

  it("returns removed: false when no rule exists", async () => {
    const result = await revokeUser("nonexistent");
    expect(result.removed).toBe(false);
  });
});
