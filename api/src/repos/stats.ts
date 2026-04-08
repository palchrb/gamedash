/**
 * Stats repository — per-user, per-service playtime counters.
 *
 * The collector calls `commit()` with a delta (seconds to add + which
 * services to mark as "currently playing") under a single mutex, so a
 * 60s tick is one atomic write even with many users.
 */

import { config } from "../config";
import { readJson, withLock, writeJson } from "../lib/atomic-file";
import {
  type StatsFile,
  StatsFileSchema,
  type UserStats,
} from "../schemas";

function filePath(): string {
  return config().statsFile;
}

export async function loadStats(): Promise<StatsFile> {
  return readJson(filePath(), StatsFileSchema, { users: {} });
}

export async function saveStats(data: StatsFile): Promise<void> {
  await writeJson(filePath(), StatsFileSchema, data);
}

export async function mutateStats<T>(
  fn: (draft: StatsFile) => Promise<T> | T,
): Promise<T> {
  return withLock(`stats:${filePath()}`, async () => {
    const draft = await loadStats();
    const result = await fn(draft);
    await saveStats(draft);
    return result;
  });
}

export function ensureBucket(stats: StatsFile, userId: string): UserStats {
  const existing = stats.users[userId];
  if (existing) return existing;
  const fresh: UserStats = {
    totalSeconds: 0,
    perService: {},
    perDay: {},
    lastPlayedAt: null,
    currentSessions: {},
  };
  stats.users[userId] = fresh;
  return fresh;
}

export function todayKey(now = new Date()): string {
  return now.toISOString().slice(0, 10);
}

export interface LeaderboardRow {
  userId: string;
  totalSeconds: number;
  lastPlayedAt: string | null;
}

export async function leaderboard(): Promise<LeaderboardRow[]> {
  const stats = await loadStats();
  return Object.entries(stats.users)
    .map(([userId, u]) => ({
      userId,
      totalSeconds: u.totalSeconds,
      lastPlayedAt: u.lastPlayedAt,
    }))
    .sort((a, b) => b.totalSeconds - a.totalSeconds);
}

export interface UserStatsSummary {
  totalSeconds: number;
  today: number;
  week: number;
  perService: Record<string, number>;
  lastPlayedAt: string | null;
}

export async function summarizeUser(userId: string): Promise<UserStatsSummary> {
  const stats = await loadStats();
  const u = stats.users[userId];
  if (!u) {
    return { totalSeconds: 0, today: 0, week: 0, perService: {}, lastPlayedAt: null };
  }
  const today = todayKey();
  const todaySec = sumValues(u.perDay[today] ?? {});
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - 6);
  let weekSec = 0;
  for (const [day, byService] of Object.entries(u.perDay)) {
    if (new Date(day) >= cutoff) weekSec += sumValues(byService);
  }
  return {
    totalSeconds: u.totalSeconds,
    today: todaySec,
    week: weekSec,
    perService: u.perService,
    lastPlayedAt: u.lastPlayedAt,
  };
}

function sumValues(obj: Record<string, number>): number {
  let total = 0;
  for (const v of Object.values(obj)) total += v;
  return total;
}
