/**
 * Tests for the stats collector — specifically the perDay pruning that
 * prevents unbounded disk growth.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resetConfigForTests } from "../config";
import { resetLoggerForTests } from "../logger";

// Mock kernel queries — no live connections during tests.
vi.mock("../firewall/connections", () => ({
  listAllConnections: vi.fn().mockResolvedValue([]),
}));

// Provide a minimal rule so tick() doesn't early-return.
vi.mock("../repos/firewall-rules", () => ({
  loadRules: vi.fn().mockResolvedValue({
    rules: [
      {
        ip: "203.0.113.1",
        userId: "u1",
        services: [{ id: "mc1", ports: [{ port: "25565", proto: "tcp" }] }],
        addedAt: new Date().toISOString(),
        expiresAt: null,
        label: "test",
      },
    ],
  }),
}));

import { StatsCollector } from "./collector";
import { loadStats, saveStats, todayKey } from "../repos/stats";
import type { StatsFile } from "../schemas";

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gamedash-stats-"));
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

function daysAgo(n: number): string {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return todayKey(d);
}

describe("StatsCollector.tick — perDay pruning", () => {
  it("prunes entries older than 90 days while keeping recent ones", async () => {
    const oldDay = daysAgo(100);
    const recentDay = daysAgo(50);
    const today = todayKey();

    const initial: StatsFile = {
      users: {
        u1: {
          totalSeconds: 3600,
          perService: { mc1: 3600 },
          perDay: {
            [oldDay]: { mc1: 1200 },
            [recentDay]: { mc1: 1200 },
            [today]: { mc1: 1200 },
          },
          lastPlayedAt: new Date().toISOString(),
          currentSessions: {},
        },
      },
    };
    await saveStats(initial);

    const collector = new StatsCollector();
    await collector.tick();

    const after = await loadStats();
    const days = Object.keys(after.users["u1"]!.perDay);
    expect(days).not.toContain(oldDay);
    expect(days).toContain(recentDay);
    expect(days).toContain(today);
  });

  it("prunes old entries across multiple users", async () => {
    const oldDay = daysAgo(95);
    const today = todayKey();

    const initial: StatsFile = {
      users: {
        u1: {
          totalSeconds: 600,
          perService: { mc1: 600 },
          perDay: { [oldDay]: { mc1: 600 }, [today]: { mc1: 0 } },
          lastPlayedAt: null,
          currentSessions: {},
        },
        u2: {
          totalSeconds: 300,
          perService: { mc1: 300 },
          perDay: { [oldDay]: { mc1: 300 } },
          lastPlayedAt: null,
          currentSessions: {},
        },
      },
    };
    await saveStats(initial);

    const collector = new StatsCollector();
    await collector.tick();

    const after = await loadStats();
    expect(Object.keys(after.users["u1"]!.perDay)).not.toContain(oldDay);
    expect(Object.keys(after.users["u2"]!.perDay)).not.toContain(oldDay);
  });

  it("keeps entries at exactly 90 days", async () => {
    const boundary = daysAgo(90);
    const initial: StatsFile = {
      users: {
        u1: {
          totalSeconds: 60,
          perService: { mc1: 60 },
          perDay: { [boundary]: { mc1: 60 } },
          lastPlayedAt: null,
          currentSessions: {},
        },
      },
    };
    await saveStats(initial);

    const collector = new StatsCollector();
    await collector.tick();

    const after = await loadStats();
    // Exactly 90 days ago should still be kept (cutoff is exclusive)
    expect(Object.keys(after.users["u1"]!.perDay)).toContain(boundary);
  });
});
