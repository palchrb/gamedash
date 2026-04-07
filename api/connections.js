/**
 * connections.js — query the host kernel for live connections to game ports.
 *
 * This is the autoritative source-of-truth for "is this IP currently playing?"
 * and replaces the previous design that parsed UFW logs. We use kernel-state
 * queries via the ufw-agent sidecar (which has pid:host + privileged) so we
 * see real established TCP connections (`ss`) and active UDP flows
 * (`conntrack`) without any logging configuration on the host.
 *
 * Used by:
 *   - users.js  →  smart-revoke ("don't kick out an active session")
 *   - stats.js  →  per-user actual playtime (not whitelist time)
 *   - server.js →  /api/active-sessions endpoint
 *
 * Performance: we batch queries. listAllConnections() returns the full
 * kernel state in two `nsenter` calls (one ss, one conntrack) regardless
 * of how many users / services are configured.
 */

const { execFile } = require("child_process");
const { nsenterArgs } = require("./firewall");

const SS_TIMEOUT_MS = 5000;
const CONNTRACK_TIMEOUT_MS = 5000;

/** Run a command via the ufw-agent + nsenter wrapper. */
function nsenterRun(args, timeout) {
  return new Promise((resolve, reject) => {
    execFile(
      "docker",
      [...nsenterArgs(), ...args],
      { timeout, maxBuffer: 4 * 1024 * 1024 },
      (err, stdout, stderr) => {
        if (err) return reject(new Error(stderr || err.message));
        resolve(stdout);
      },
    );
  });
}

/**
 * Get all currently established TCP connections on the host.
 * Returns an array of { srcIp, dstPort } objects.
 *
 * Output format from `ss -tnH state established`:
 *   ESTAB 0  0     192.0.2.10:25565    203.0.113.45:51234
 * (header suppressed via -H, columns: state recv-q send-q local peer)
 */
async function listEstablishedTcp() {
  let stdout;
  try {
    stdout = await nsenterRun(["ss", "-tnH", "state", "established"], SS_TIMEOUT_MS);
  } catch (err) {
    // ss can fail when no connections exist on some kernels — treat as empty
    if (/no such file|not found/i.test(err.message)) return [];
    throw err;
  }

  const out = [];
  for (const line of stdout.split("\n")) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 5) continue;
    // parts: [state, recv-q, send-q, local, peer]
    const local = parts[3];
    const peer = parts[4];
    const localPort = parseLastColon(local);
    const peerHost = stripPort(peer);
    if (!localPort || !peerHost) continue;
    out.push({ srcIp: peerHost, dstPort: String(localPort), proto: "tcp" });
  }
  return out;
}

/**
 * Get all currently tracked UDP flows on the host.
 * Returns an array of { srcIp, dstPort } objects.
 *
 * Output format from `conntrack -L -p udp -o extended` is verbose:
 *   udp 17 28 src=203.0.113.45 dst=192.0.2.10 sport=51234 dport=19132 ...
 */
async function listUdpFlows() {
  let stdout;
  try {
    stdout = await nsenterRun(["conntrack", "-L", "-p", "udp"], CONNTRACK_TIMEOUT_MS);
  } catch (err) {
    // conntrack-tools may not be installed — degrade gracefully
    if (/not found|no such file|conntrack/i.test(err.message)) return [];
    return [];
  }

  const out = [];
  for (const line of stdout.split("\n")) {
    if (!line.startsWith("udp")) continue;
    // First src=/dport= pair is original direction (client → server)
    const srcMatch = line.match(/src=([\d.]+)/);
    const dportMatch = line.match(/dport=(\d+)/);
    if (!srcMatch || !dportMatch) continue;
    out.push({ srcIp: srcMatch[1], dstPort: String(dportMatch[1]), proto: "udp" });
  }
  return out;
}

/**
 * Batched query — returns all live game-port connections once.
 * Pass through ports the caller cares about to filter the result;
 * if omitted, returns ALL established connections.
 */
async function listAllConnections(filterPorts) {
  const [tcp, udp] = await Promise.all([
    listEstablishedTcp().catch((err) => {
      console.error("connections: ss failed:", err.message);
      return [];
    }),
    listUdpFlows().catch((err) => {
      console.error("connections: conntrack failed:", err.message);
      return [];
    }),
  ]);
  const all = [...tcp, ...udp];
  if (!filterPorts || filterPorts.length === 0) return all;
  const wanted = new Set(filterPorts.map((p) => `${p.port}/${p.proto}`));
  return all.filter((c) => wanted.has(`${c.dstPort}/${c.proto}`));
}

/**
 * Check if a specific IP currently has any live connection to one of
 * the given game ports. Used by users.js smart-revoke before killing
 * an existing rule.
 */
async function isIpActiveOnPorts(ip, ports) {
  if (!ip || !ports || ports.length === 0) return { active: false };
  const conns = await listAllConnections(ports);
  const matches = conns.filter((c) => c.srcIp === ip);
  return { active: matches.length > 0, matchCount: matches.length };
}

function parseLastColon(addr) {
  // IPv4: "192.0.2.10:25565" → "25565"
  // IPv6 with brackets: "[::1]:25565" → "25565"
  const i = addr.lastIndexOf(":");
  if (i < 0) return null;
  return addr.slice(i + 1);
}

function stripPort(addr) {
  if (addr.startsWith("[")) {
    const close = addr.indexOf("]");
    if (close > 0) return addr.slice(1, close);
  }
  const i = addr.lastIndexOf(":");
  if (i < 0) return addr;
  return addr.slice(0, i);
}

module.exports = {
  listEstablishedTcp,
  listUdpFlows,
  listAllConnections,
  isIpActiveOnPorts,
};
