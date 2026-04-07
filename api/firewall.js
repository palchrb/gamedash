/**
 * Firewall (UFW) module — generalized.
 *
 * The original `server.js` had a hardcoded UFW_PORTS list and called
 * `ufwExec(action, ip, port, proto)` once per port. This module replaces
 * that with a port-list-aware API that takes the ports the caller wants
 * to open / close, and a `firewall-rules.json` schema that records exactly
 * which (service, port, proto) tuples were opened so revocation works
 * across registry changes.
 *
 * Schema for /mcdata/firewall-rules.json:
 *   {
 *     "rules": [
 *       {
 *         "ip": "203.0.113.45",
 *         "addedAt": "2026-04-07T13:42:00.000Z",
 *         "expiresAt": "2026-04-08T13:42:00.000Z",   // optional
 *         "label": "Lars via mc1,impostor",
 *         "userId": "u_lars",                          // optional (legacy rules omit it)
 *         "services": [
 *           { "id": "mc1",      "ports": [{"port":"25565","proto":"tcp"}] },
 *           { "id": "impostor", "ports": [{"port":"22023","proto":"tcp"},{"port":"22023","proto":"udp"}] }
 *         ]
 *       }
 *     ]
 *   }
 *
 * The legacy schema (just `{ip, addedAt, expiresAt, label}` without
 * `services`) is auto-migrated on first load by attaching the configured
 * default service so existing rules keep working.
 */

const fs = require("fs");
const { execFile } = require("child_process");

const FIREWALL_RULES_FILE = process.env.FIREWALL_RULES_FILE || "/mcdata/firewall-rules.json";
const UFW_AGENT_CONTAINER = process.env.UFW_AGENT_CONTAINER || "ufw-agent";

function nsenterArgs() {
  return [
    "exec", UFW_AGENT_CONTAINER,
    "nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--",
  ];
}

/** Allow one IP/port/proto combination through UFW. */
function ufwAllow(ip, port, proto) {
  return new Promise((resolve, reject) => {
    execFile(
      "docker",
      [...nsenterArgs(), "ufw", "route", "allow", "from", ip, "to", "any", "port", String(port), "proto", proto],
      { timeout: 15000 },
      (err, stdout, stderr) => {
        if (err) return reject(new Error(stderr || err.message));
        resolve(stdout.trim());
      },
    );
  });
}

/** Delete one IP/port/proto allow rule from UFW. */
function ufwDelete(ip, port, proto) {
  return new Promise((resolve, reject) => {
    execFile(
      "docker",
      [...nsenterArgs(), "ufw", "route", "delete", "allow", "from", ip, "to", "any", "port", String(port), "proto", proto],
      { timeout: 15000 },
      (err, stdout, stderr) => {
        if (err) return reject(new Error(stderr || err.message));
        resolve(stdout.trim());
      },
    );
  });
}

/** Apply allow on a list of {port,proto}. Continues on individual errors and returns the list of failures. */
async function ufwAllowMany(ip, ports) {
  const errors = [];
  for (const { port, proto } of ports) {
    try {
      await ufwAllow(ip, port, proto);
    } catch (err) {
      errors.push({ port, proto, error: err.message });
    }
  }
  return errors;
}

/** Apply delete on a list of {port,proto}. */
async function ufwDeleteMany(ip, ports) {
  const errors = [];
  for (const { port, proto } of ports) {
    try {
      await ufwDelete(ip, port, proto);
    } catch (err) {
      errors.push({ port, proto, error: err.message });
    }
  }
  return errors;
}

function loadRules() {
  try {
    if (fs.existsSync(FIREWALL_RULES_FILE)) {
      const data = JSON.parse(fs.readFileSync(FIREWALL_RULES_FILE, "utf8"));
      if (!data.rules) data.rules = [];
      return data;
    }
  } catch (e) {
    console.error("firewall: failed to load rules:", e.message);
  }
  return { rules: [] };
}

function saveRules(data) {
  fs.writeFileSync(FIREWALL_RULES_FILE, JSON.stringify(data, null, 2));
}

/**
 * Auto-migrate legacy rules that lack a `services` field. Attaches the given
 * legacy port set under a "legacy" service id so revocation still works.
 */
function migrateLegacyRules(legacyPorts) {
  const data = loadRules();
  let changed = false;
  for (const rule of data.rules) {
    if (!rule.services || !Array.isArray(rule.services) || rule.services.length === 0) {
      rule.services = [{ id: "legacy", ports: legacyPorts }];
      changed = true;
    }
  }
  if (changed) saveRules(data);
  return data;
}

/** Flatten a rule's services into a deduplicated [{port,proto}] list. */
function flattenPorts(rule) {
  const seen = new Set();
  const out = [];
  for (const svc of rule.services || []) {
    for (const p of svc.ports || []) {
      const key = `${p.port}/${p.proto}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ port: String(p.port), proto: p.proto });
    }
  }
  return out;
}

function findRuleByIp(ip) {
  return loadRules().rules.find((r) => r.ip === ip) || null;
}

function findRuleByUserId(userId) {
  return loadRules().rules.find((r) => r.userId === userId) || null;
}

function upsertRule(rule) {
  const data = loadRules();
  const idx = data.rules.findIndex((r) =>
    rule.userId ? r.userId === rule.userId : r.ip === rule.ip,
  );
  if (idx >= 0) data.rules[idx] = rule;
  else data.rules.push(rule);
  saveRules(data);
}

function deleteRuleByIp(ip) {
  const data = loadRules();
  data.rules = data.rules.filter((r) => r.ip !== ip);
  saveRules(data);
}

function deleteRuleByUserId(userId) {
  const data = loadRules();
  data.rules = data.rules.filter((r) => r.userId !== userId);
  saveRules(data);
}

/** Strict IPv4 validation - rejects private, loopback, multicast, reserved. */
function isValidPublicIPv4(ip) {
  if (typeof ip !== "string") return false;
  const match = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!match) return false;
  const parts = [match[1], match[2], match[3], match[4]];
  const octets = parts.map(Number);
  if (octets.some((o) => o > 255)) return false;
  if (parts.some((s) => s.length > 1 && s.startsWith("0"))) return false;
  const [a, b] = octets;
  if (a === 0) return false;
  if (a === 10) return false;
  if (a === 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a >= 224) return false;
  return true;
}

module.exports = {
  FIREWALL_RULES_FILE,
  ufwAllow,
  ufwDelete,
  ufwAllowMany,
  ufwDeleteMany,
  loadRules,
  saveRules,
  migrateLegacyRules,
  flattenPorts,
  findRuleByIp,
  findRuleByUserId,
  upsertRule,
  deleteRuleByIp,
  deleteRuleByUserId,
  isValidPublicIPv4,
  nsenterArgs,
};
