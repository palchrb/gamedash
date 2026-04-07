/**
 * Users module — per-child knock tokens, one active IP per user, 24h TTL,
 * smart-revoke that protects active sessions.
 *
 * Each user has:
 *   - id              opaque short id (used in URLs and audit log)
 *   - name            display name (e.g. "Lars")
 *   - token           ~256-bit URL-safe random token (in /u/<token> URL)
 *   - allowedServices array of service ids the user is permitted to knock
 *   - locale          optional ISO language code (overrides DEFAULT_LOCALE in PWA)
 *   - createdAt       ISO timestamp
 *   - history         last N knocks (ip, ua, services, at)
 *
 * Storage: /mcdata/users.json
 * Audit log: /mcdata/audit.log (JSONL, one event per line)
 *
 * The active-IP state is stored on the firewall rule itself (rule.userId,
 * rule.expiresAt), not on the user, so smart-revoke only needs to consult
 * one source of truth (`firewall.json`) for "what's currently allowed".
 */

const fs = require("fs-extra");
const crypto = require("crypto");
const path = require("path");
const firewall = require("./firewall");
const connections = require("./connections");

const USERS_FILE = process.env.USERS_FILE || "/mcdata/users.json";
const AUDIT_LOG = process.env.AUDIT_LOG || "/mcdata/audit.log";
const KNOCK_USER_TTL_MS =
  (parseInt(process.env.KNOCK_USER_TTL_HOURS, 10) || 24) * 60 * 60 * 1000;
const HISTORY_MAX = 20;

function loadUsers() {
  try {
    if (fs.existsSync(USERS_FILE)) {
      const data = JSON.parse(fs.readFileSync(USERS_FILE, "utf8"));
      if (!data.users) data.users = [];
      return data;
    }
  } catch (e) {
    console.error("users: failed to load:", e.message);
  }
  return { users: [] };
}

function saveUsers(data) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2));
}

function audit(event) {
  try {
    fs.appendFileSync(
      AUDIT_LOG,
      JSON.stringify({ at: new Date().toISOString(), ...event }) + "\n",
    );
  } catch (err) {
    console.error("users: audit log write failed:", err.message);
  }
}

function generateToken() {
  return crypto.randomBytes(32).toString("base64url");
}

function generateUserId(name) {
  const safe = (name || "user").toLowerCase().replace(/[^a-z0-9]+/g, "_").slice(0, 16);
  const suffix = crypto.randomBytes(3).toString("hex");
  return `u_${safe}_${suffix}`;
}

/** Constant-time token comparison to avoid timing attacks. */
function constantTimeEquals(a, b) {
  const ab = Buffer.from(String(a || ""));
  const bb = Buffer.from(String(b || ""));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function findByToken(token) {
  if (!token) return null;
  const data = loadUsers();
  for (const u of data.users) {
    if (u.token && constantTimeEquals(u.token, token)) return u;
  }
  return null;
}

function findById(id) {
  if (!id) return null;
  const data = loadUsers();
  return data.users.find((u) => u.id === id) || null;
}

function listUsers() {
  const data = loadUsers();
  return data.users.map((u) => ({ ...u, token: undefined }));
}

function listUsersWithTokens() {
  return loadUsers().users;
}

function createUser({ name, allowedServices = [], locale }) {
  const data = loadUsers();
  if (!name || typeof name !== "string") {
    throw new Error("Missing user name");
  }
  if (data.users.some((u) => u.name.toLowerCase() === name.toLowerCase())) {
    throw new Error("A user with that name already exists");
  }
  const user = {
    id: generateUserId(name),
    name,
    token: generateToken(),
    allowedServices: Array.isArray(allowedServices) ? allowedServices : [],
    locale: locale || null,
    createdAt: new Date().toISOString(),
    history: [],
  };
  data.users.push(user);
  saveUsers(data);
  audit({ kind: "user.create", userId: user.id, name: user.name });
  return user;
}

function updateUser(id, patch) {
  const data = loadUsers();
  const user = data.users.find((u) => u.id === id);
  if (!user) throw new Error("User not found");
  if (patch.name) user.name = patch.name;
  if (Array.isArray(patch.allowedServices)) user.allowedServices = patch.allowedServices;
  if (patch.locale !== undefined) user.locale = patch.locale || null;
  saveUsers(data);
  audit({ kind: "user.update", userId: user.id });
  return { ...user, token: undefined };
}

function deleteUser(id) {
  const data = loadUsers();
  const user = data.users.find((u) => u.id === id);
  if (!user) throw new Error("User not found");
  data.users = data.users.filter((u) => u.id !== id);
  saveUsers(data);
  // Also revoke any active firewall rule for the user
  const rule = firewall.findRuleByUserId(id);
  if (rule) {
    firewall.deleteRuleByUserId(id);
    firewall.ufwDeleteMany(rule.ip, firewall.flattenPorts(rule)).catch((err) =>
      console.error("users.delete ufw cleanup failed:", err.message),
    );
  }
  audit({ kind: "user.delete", userId: id, name: user.name });
}

function rotateToken(id) {
  const data = loadUsers();
  const user = data.users.find((u) => u.id === id);
  if (!user) throw new Error("User not found");
  user.token = generateToken();
  saveUsers(data);
  audit({ kind: "user.rotate_token", userId: id });
  return user.token;
}

function pushHistory(userId, entry) {
  const data = loadUsers();
  const user = data.users.find((u) => u.id === userId);
  if (!user) return;
  user.history = (user.history || []).slice(-HISTORY_MAX + 1);
  user.history.push(entry);
  saveUsers(data);
}

/**
 * Resolve which services to knock for a request.
 * Accepts:
 *   - "all" → all of user.allowedServices
 *   - array of ids → intersection with user.allowedServices
 *   - undefined → all
 */
function resolveServices(user, requested) {
  const allowed = new Set(user.allowedServices || []);
  if (!requested || requested === "all") return Array.from(allowed);
  const wanted = Array.isArray(requested) ? requested : [requested];
  return wanted.filter((id) => allowed.has(id));
}

/**
 * Core knock entry point — used by the user-facing PWA flow.
 *
 * Behavior:
 *   1. Constant-time token verification (caller does this and passes user).
 *   2. Look up the existing rule for this user.
 *   3. If same IP → renew expiresAt.
 *   4. If different IP → check if old IP has an active connection on any
 *      of the requested ports (smart-revoke). If yes, return
 *      { requireConfirm: true } unless options.force is set.
 *   5. Otherwise: revoke old IP, allow new IP, write new rule, append history.
 *
 * Returns one of:
 *   { ok: true, rule, expiresAt }
 *   { requireConfirm: true, oldIp, oldIpActive: true, lastSeenSecondsAgo, oldServices }
 *   throws on hard errors
 */
async function knockUser(user, ip, requestedServices, options = {}) {
  if (!firewall.isValidPublicIPv4(ip)) {
    throw new Error("Invalid or non-public IPv4 address");
  }
  const serviceIds = resolveServices(user, requestedServices);
  if (serviceIds.length === 0) {
    throw new Error("No services requested or allowed");
  }

  const registry = options.registry;
  if (!registry) throw new Error("Registry not provided");

  const portList = registry.collectPorts(serviceIds);
  if (portList.length === 0) {
    throw new Error("No ports configured for requested services");
  }

  const existing = firewall.findRuleByUserId(user.id);
  const now = Date.now();
  const expiresAt = new Date(now + KNOCK_USER_TTL_MS).toISOString();

  // Same IP → renew
  if (existing && existing.ip === ip) {
    existing.expiresAt = expiresAt;
    existing.services = registry.buildRuleServices(serviceIds);
    existing.label = `${user.name} via ${serviceIds.join(",")}`;
    firewall.upsertRule(existing);
    // Make sure all needed ports are actually open (in case service list changed)
    const errors = await firewall.ufwAllowMany(ip, firewall.flattenPorts(existing));
    pushHistory(user.id, {
      ip,
      at: new Date().toISOString(),
      services: serviceIds,
      ua: options.ua || null,
      kind: "renew",
    });
    audit({ kind: "knock.renew", userId: user.id, ip, services: serviceIds });
    return { ok: true, rule: existing, expiresAt, errors };
  }

  // Different IP → smart-revoke check
  if (existing && existing.ip !== ip && !options.force) {
    const oldPorts = firewall.flattenPorts(existing);
    const active = await connections.isIpActiveOnPorts(existing.ip, oldPorts);
    if (active.active) {
      audit({
        kind: "knock.blocked_active_session",
        userId: user.id,
        oldIp: existing.ip,
        newIp: ip,
        active: active.matchCount,
      });
      return {
        requireConfirm: "active_session",
        oldIp: existing.ip,
        oldIpActive: true,
        lastSeenSecondsAgo: 0,
        oldServices: (existing.services || []).map((s) => s.id),
      };
    }
  }

  // Different IP → safe to swap
  if (existing && existing.ip !== ip) {
    try {
      await firewall.ufwDeleteMany(existing.ip, firewall.flattenPorts(existing));
    } catch (err) {
      console.error("knockUser: ufwDeleteMany failed:", err.message);
    }
    firewall.deleteRuleByUserId(user.id);
    audit({
      kind: "knock.revoke",
      userId: user.id,
      ip: existing.ip,
      reason: "ip_change",
    });
  }

  // Apply allow on new IP
  const errors = await firewall.ufwAllowMany(ip, portList);
  const rule = {
    ip,
    addedAt: new Date().toISOString(),
    expiresAt,
    label: `${user.name} via ${serviceIds.join(",")}`,
    userId: user.id,
    services: registry.buildRuleServices(serviceIds),
  };
  firewall.upsertRule(rule);
  pushHistory(user.id, {
    ip,
    at: rule.addedAt,
    services: serviceIds,
    ua: options.ua || null,
    kind: "knock",
  });
  audit({ kind: "knock.allow", userId: user.id, ip, services: serviceIds });
  return { ok: true, rule, expiresAt, errors };
}

/** Manually revoke a user's active rule (admin or self-service). */
async function revokeUser(userId) {
  const rule = firewall.findRuleByUserId(userId);
  if (!rule) return { ok: true, removed: false };
  try {
    await firewall.ufwDeleteMany(rule.ip, firewall.flattenPorts(rule));
  } catch (err) {
    console.error("revokeUser: ufw delete failed:", err.message);
  }
  firewall.deleteRuleByUserId(userId);
  audit({ kind: "knock.revoke_manual", userId, ip: rule.ip });
  return { ok: true, removed: true, ip: rule.ip };
}

/** Run the periodic auto-expire sweep on user-owned rules. */
async function sweepExpiredRules() {
  const data = firewall.loadRules();
  const now = Date.now();
  const expired = data.rules.filter(
    (r) => r.expiresAt && new Date(r.expiresAt).getTime() < now,
  );
  for (const rule of expired) {
    try {
      await firewall.ufwDeleteMany(rule.ip, firewall.flattenPorts(rule));
      audit({
        kind: "knock.auto_expire",
        userId: rule.userId || null,
        ip: rule.ip,
      });
      console.log(`Auto-expired: ${rule.ip}${rule.userId ? ` (${rule.userId})` : ""}`);
    } catch (err) {
      console.error(`Failed to expire ${rule.ip}:`, err.message);
    }
  }
  if (expired.length > 0) {
    data.rules = data.rules.filter(
      (r) => !r.expiresAt || new Date(r.expiresAt).getTime() >= now,
    );
    firewall.saveRules(data);
  }
  return expired.length;
}

module.exports = {
  USERS_FILE,
  KNOCK_USER_TTL_MS,
  loadUsers,
  saveUsers,
  listUsers,
  listUsersWithTokens,
  createUser,
  updateUser,
  deleteUser,
  rotateToken,
  findByToken,
  findById,
  knockUser,
  revokeUser,
  sweepExpiredRules,
  resolveServices,
  audit,
};
