/**
 * Playtime collector — runs every 60s, queries live kernel state, and
 * increments per-(user, service, day) counters for every user whose
 * whitelisted IP currently has a real game connection.
 *
 * Measures REAL playtime (time with a live connection), not whitelist
 * time. A user who knocks at 09:00 and plays 30 min has 30 min
 * recorded even though the firewall stays open for 24 h.
 */

import { listAllConnections } from "../firewall/connections";
import { loadRules } from "../repos/firewall-rules";
import { ensureBucket, mutateStats, todayKey } from "../repos/stats";
import { logger } from "../logger";
import type { PortSpec } from "../schemas";

const COLLECTOR_INTERVAL_MS = 60_000;
const INCREMENT_SECONDS = 60;
const PRUNE_DAYS = 90;

export class StatsCollector {
  private timer: NodeJS.Timeout | null = null;

  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => {
      this.tick().catch((err: Error) => {
        logger().warn({ err: err.message }, "stats tick failed");
      });
    }, COLLECTOR_INTERVAL_MS);
    logger().info({ intervalMs: COLLECTOR_INTERVAL_MS }, "stats collector started");
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  async tick(): Promise<void> {
    const fw = await loadRules();
    if (fw.rules.length === 0) return;

    // Build { ip → [{userId, serviceId, ports}] } lookup.
    const ipMap = new Map<
      string,
      Array<{ userId: string; serviceId: string; ports: PortSpec[] }>
    >();
    for (const rule of fw.rules) {
      if (!rule.userId) continue;
      for (const svc of rule.services) {
        const entry = ipMap.get(rule.ip) ?? [];
        entry.push({ userId: rule.userId, serviceId: svc.id, ports: svc.ports });
        ipMap.set(rule.ip, entry);
      }
    }
    if (ipMap.size === 0) return;

    // One batched kernel query for every port anyone cares about.
    const seenPorts = new Set<string>();
    const allPorts: PortSpec[] = [];
    for (const entries of ipMap.values()) {
      for (const e of entries) {
        for (const p of e.ports) {
          const key = `${p.port}/${p.proto}`;
          if (seenPorts.has(key)) continue;
          seenPorts.add(key);
          allPorts.push(p);
        }
      }
    }

    const conns = await listAllConnections(allPorts);
    const liveByIp = new Map<string, Set<string>>();
    for (const c of conns) {
      const set = liveByIp.get(c.srcIp) ?? new Set<string>();
      set.add(`${c.dstPort}/${c.proto}`);
      liveByIp.set(c.srcIp, set);
    }

    const day = todayKey();
    const nowIso = new Date().toISOString();

    // Prune cutoff: ISO date string for PRUNE_DAYS ago.
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - PRUNE_DAYS);
    const cutoffKey = todayKey(cutoff);

    await mutateStats((draft) => {
      for (const [ip, entries] of ipMap.entries()) {
        const live = liveByIp.get(ip) ?? new Set<string>();
        for (const e of entries) {
          const user = ensureBucket(draft, e.userId);
          const wantedKeys = e.ports.map((p) => `${p.port}/${p.proto}`);
          const playing = wantedKeys.some((k) => live.has(k));
          if (playing) {
            user.totalSeconds += INCREMENT_SECONDS;
            user.perService[e.serviceId] =
              (user.perService[e.serviceId] ?? 0) + INCREMENT_SECONDS;
            const dayBucket = user.perDay[day] ?? {};
            dayBucket[e.serviceId] = (dayBucket[e.serviceId] ?? 0) + INCREMENT_SECONDS;
            user.perDay[day] = dayBucket;
            user.lastPlayedAt = nowIso;
            if (!user.currentSessions[e.serviceId]) {
              user.currentSessions[e.serviceId] = nowIso;
            }
          } else if (user.currentSessions[e.serviceId]) {
            delete user.currentSessions[e.serviceId];
          }
        }
      }

      // Prune perDay entries older than PRUNE_DAYS to prevent unbounded growth.
      for (const user of Object.values(draft.users)) {
        for (const dayKey of Object.keys(user.perDay)) {
          if (dayKey < cutoffKey) delete user.perDay[dayKey];
        }
      }
    });
  }
}

let _collector: StatsCollector | null = null;

export function statsCollector(): StatsCollector {
  if (!_collector) _collector = new StatsCollector();
  return _collector;
}
