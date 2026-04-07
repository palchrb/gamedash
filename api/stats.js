/**
 * Stats collector — measures actual playtime per user per service.
 *
 * Approach: every 60s, run one batched ss + conntrack query, and for every
 * user that currently has at least one live connection on one of their
 * whitelisted ports, increment the per-(user, service, day) counter by 60.
 *
 * This measures REAL playtime (time with a live connection), not whitelist
 * time (time the firewall has stood open). A user who knocks at 09:00 and
 * plays 30 min has 30 min real playtime even though the firewall stays open
 * for 24h.
 *
 * Storage: /mcdata/stats.json
 *   {
 *     "users": {
 *       "u_lars": {
 *         "totalSeconds": 1234,
 *         "perService": { "mc1": 1000, "impostor": 234 },
 *         "perDay": {
 *           "2026-04-07": { "mc1": 600, "impostor": 234 },
 *           "2026-04-08": { "mc1": 400 }
 *         },
 *         "lastPlayedAt": "2026-04-07T15:23:00.000Z",
 *         "currentSessions": { "mc1": "2026-04-07T14:11:00.000Z" }
 *       }
 *     }
 *   }
 */

const fs = require("fs-extra");
const firewall = require("./firewall");
const connections = require("./connections");

const STATS_FILE = process.env.STATS_FILE || "/mcdata/stats.json";
const COLLECTOR_INTERVAL_MS = 60 * 1000;
let intervalHandle = null;
let registryRef = null;

function loadStats() {
  try {
    if (fs.existsSync(STATS_FILE)) {
      const data = JSON.parse(fs.readFileSync(STATS_FILE, "utf8"));
      if (!data.users) data.users = {};
      return data;
    }
  } catch (err) {
    console.error("stats: failed to load:", err.message);
  }
  return { users: {} };
}

function saveStats(data) {
  fs.writeFileSync(STATS_FILE, JSON.stringify(data, null, 2));
}

function todayKey() {
  return new Date().toISOString().slice(0, 10);
}

function ensureUserBucket(stats, userId) {
  if (!stats.users[userId]) {
    stats.users[userId] = {
      totalSeconds: 0,
      perService: {},
      perDay: {},
      lastPlayedAt: null,
      currentSessions: {},
    };
  }
  const u = stats.users[userId];
  if (!u.perService) u.perService = {};
  if (!u.perDay) u.perDay = {};
  if (!u.currentSessions) u.currentSessions = {};
  return u;
}

/**
 * Run one collector tick. Public so callers can trigger it manually
 * (and so tests can call it without waiting for the interval).
 */
async function tick() {
  if (!registryRef) return;
  const fwData = firewall.loadRules();
  if (fwData.rules.length === 0) return;

  // Build map: ip → list of {userId, serviceId, ports[]}
  const ipMap = new Map();
  for (const rule of fwData.rules) {
    if (!rule.userId) continue;
    for (const svc of rule.services || []) {
      const entry = ipMap.get(rule.ip) || [];
      entry.push({ userId: rule.userId, serviceId: svc.id, ports: svc.ports });
      ipMap.set(rule.ip, entry);
    }
  }
  if (ipMap.size === 0) return;

  // One batched query for all live connections on all relevant ports
  const allWantedPorts = [];
  const seenPort = new Set();
  for (const entries of ipMap.values()) {
    for (const e of entries) {
      for (const p of e.ports) {
        const key = `${p.port}/${p.proto}`;
        if (seenPort.has(key)) continue;
        seenPort.add(key);
        allWantedPorts.push({ port: String(p.port), proto: p.proto });
      }
    }
  }

  let conns;
  try {
    conns = await connections.listAllConnections(allWantedPorts);
  } catch (err) {
    console.error("stats: connection query failed:", err.message);
    return;
  }

  // Group connections by srcIp
  const liveByIp = new Map();
  for (const c of conns) {
    if (!liveByIp.has(c.srcIp)) liveByIp.set(c.srcIp, []);
    liveByIp.get(c.srcIp).push(c);
  }

  const stats = loadStats();
  const day = todayKey();
  const nowIso = new Date().toISOString();
  let changed = false;

  for (const [ip, entries] of ipMap.entries()) {
    const live = liveByIp.get(ip) || [];
    if (live.length === 0) {
      // Close any open sessions for this user/service combo
      for (const e of entries) {
        const u = ensureUserBucket(stats, e.userId);
        if (u.currentSessions[e.serviceId]) {
          delete u.currentSessions[e.serviceId];
          changed = true;
        }
      }
      continue;
    }

    for (const e of entries) {
      const wantedKeys = new Set(e.ports.map((p) => `${p.port}/${p.proto}`));
      const hit = live.find((c) => wantedKeys.has(`${c.dstPort}/${c.proto}`));
      if (!hit) continue;

      const u = ensureUserBucket(stats, e.userId);
      u.totalSeconds = (u.totalSeconds || 0) + 60;
      u.perService[e.serviceId] = (u.perService[e.serviceId] || 0) + 60;
      if (!u.perDay[day]) u.perDay[day] = {};
      u.perDay[day][e.serviceId] = (u.perDay[day][e.serviceId] || 0) + 60;
      u.lastPlayedAt = nowIso;
      if (!u.currentSessions[e.serviceId]) {
        u.currentSessions[e.serviceId] = nowIso;
      }
      changed = true;
    }
  }

  if (changed) saveStats(stats);
}

function start(registry) {
  registryRef = registry;
  if (intervalHandle) clearInterval(intervalHandle);
  intervalHandle = setInterval(() => {
    tick().catch((err) => console.error("stats tick error:", err.message));
  }, COLLECTOR_INTERVAL_MS);
  console.log(`stats: collector started (${COLLECTOR_INTERVAL_MS / 1000}s interval)`);
}

function stop() {
  if (intervalHandle) clearInterval(intervalHandle);
  intervalHandle = null;
}

function userStats(userId) {
  const stats = loadStats();
  return stats.users[userId] || null;
}

function summarizeUser(userId) {
  const u = userStats(userId);
  if (!u) return { totalSeconds: 0, today: 0, week: 0, perService: {} };
  const today = todayKey();
  const todaySec = Object.values(u.perDay[today] || {}).reduce(
    (a, b) => a + b,
    0,
  );
  // Last 7 days
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - 6);
  let weekSec = 0;
  for (const [day, byService] of Object.entries(u.perDay || {})) {
    if (new Date(day) >= cutoff) {
      weekSec += Object.values(byService).reduce((a, b) => a + b, 0);
    }
  }
  return {
    totalSeconds: u.totalSeconds || 0,
    today: todaySec,
    week: weekSec,
    perService: u.perService || {},
    lastPlayedAt: u.lastPlayedAt || null,
  };
}

function leaderboard() {
  const stats = loadStats();
  return Object.entries(stats.users)
    .map(([userId, u]) => ({
      userId,
      totalSeconds: u.totalSeconds || 0,
      lastPlayedAt: u.lastPlayedAt || null,
    }))
    .sort((a, b) => b.totalSeconds - a.totalSeconds);
}

module.exports = {
  STATS_FILE,
  start,
  stop,
  tick,
  userStats,
  summarizeUser,
  leaderboard,
  loadStats,
};
