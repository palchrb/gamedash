/**
 * Kernel connection state queries via the sidecar HTTP API.
 *
 * This is the authoritative source for "is this IP currently playing?"
 * Used by:
 *   - smart-revoke   (don't kick out an active session)
 *   - stats collector (accumulate per-user playtime)
 *   - /api/active-sessions endpoint
 *
 * In multi-node mode we fan out to each node's sidecar and tag every
 * LiveConnection with the node it came from. Caching is per-node so a
 * flaky remote node doesn't invalidate local results.
 */

import { logger } from "../logger";
import { sidecarTcpConnections, sidecarUdpConnections } from "../lib/nsenter";
import type { FirewallRule, NodeConfig, PortSpec } from "../schemas";

export interface LiveConnection {
  srcIp: string;
  dstPort: string;
  proto: "tcp" | "udp";
  node: string;
}

// ── Per-node cache ─────────────────────────────────────────────────────
const CONN_CACHE_TTL_MS = 5_000;
const _connCache = new Map<string, { data: LiveConnection[]; expiresAt: number }>();

function parseTcp(stdout: string, nodeId: string): LiveConnection[] {
  if (!stdout) return [];
  const out: LiveConnection[] = [];
  for (const line of stdout.split("\n")) {
    const parts = line.trim().split(/\s+/u);
    if (parts.length < 5) continue;
    const local = parts[3];
    const peer = parts[4];
    if (!local || !peer) continue;
    const localPort = parseLastColon(local);
    const peerHost = stripPort(peer);
    if (!localPort || !peerHost) continue;
    out.push({ srcIp: peerHost, dstPort: localPort, proto: "tcp", node: nodeId });
  }
  return out;
}

function parseUdp(stdout: string, nodeId: string): LiveConnection[] {
  if (!stdout) return [];
  const out: LiveConnection[] = [];
  for (const line of stdout.split("\n")) {
    if (!/(^|\s)udp(\s|$)/u.test(line)) continue;
    const srcMatch = line.match(/src=(\S+)/u);
    const dportMatch = line.match(/dport=(\d+)/u);
    if (!srcMatch || !dportMatch) continue;
    out.push({ srcIp: srcMatch[1]!, dstPort: dportMatch[1]!, proto: "udp", node: nodeId });
  }
  return out;
}

async function fetchNodeConnections(
  nodeId: string,
  node: NodeConfig,
): Promise<LiveConnection[]> {
  const now = Date.now();
  const cached = _connCache.get(nodeId);
  if (cached && cached.expiresAt > now) return cached.data;

  const [tcp, udp] = await Promise.all([
    sidecarTcpConnections(node).catch((err: Error) => {
      logger().warn({ node: nodeId, err: err.message }, "ss query failed");
      return "";
    }),
    sidecarUdpConnections(node).catch((err: Error) => {
      logger().warn({ node: nodeId, err: err.message }, "conntrack query failed");
      return "";
    }),
  ]);

  const data = [...parseTcp(tcp, nodeId), ...parseUdp(udp, nodeId)];
  _connCache.set(nodeId, { data, expiresAt: now + CONN_CACHE_TTL_MS });
  return data;
}

/**
 * Fan out to all given nodes and return a unified, node-tagged connection list.
 * Optionally filter to only the ports we care about.
 */
export async function listAllConnections(
  nodeConfigs: ReadonlyMap<string, NodeConfig>,
  filterPorts?: readonly PortSpec[],
): Promise<LiveConnection[]> {
  const results = await Promise.all(
    Array.from(nodeConfigs.entries()).map(([nodeId, node]) =>
      fetchNodeConnections(nodeId, node),
    ),
  );
  const all = results.flat();
  if (!filterPorts || filterPorts.length === 0) return all;
  const wanted = new Set(filterPorts.map((p) => `${p.port}/${p.proto}`));
  return all.filter((c) => wanted.has(`${c.dstPort}/${c.proto}`));
}

export interface ActiveCheckResult {
  active: boolean;
  matchCount: number;
}

/**
 * Rule-aware active check: for each service in the rule, query its specific
 * node's connections and match against that service's ports. Returns active
 * if *any* of the rule's IPs has a live connection on any service/port.
 */
export async function isAnyIpActiveForRule(
  rule: FirewallRule,
  resolveNode: (nodeId: string) => NodeConfig,
): Promise<ActiveCheckResult> {
  if (rule.ips.length === 0 || rule.services.length === 0) {
    return { active: false, matchCount: 0 };
  }

  const ipSet = new Set(rule.ips);
  let totalMatches = 0;

  // Group services by node to batch connection queries
  const nodeServices = new Map<string, PortSpec[]>();
  for (const svc of rule.services) {
    const nodeId = svc.node ?? "local";
    let ports = nodeServices.get(nodeId);
    if (!ports) {
      ports = [];
      nodeServices.set(nodeId, ports);
    }
    for (const p of svc.ports) ports.push(p);
  }

  const checks = await Promise.all(
    Array.from(nodeServices.entries()).map(async ([nodeId, ports]) => {
      try {
        const node = resolveNode(nodeId);
        const conns = await fetchNodeConnections(nodeId, node);
        const wanted = new Set(ports.map((p) => `${p.port}/${p.proto}`));
        return conns.filter(
          (c) => ipSet.has(c.srcIp) && wanted.has(`${c.dstPort}/${c.proto}`),
        ).length;
      } catch {
        return 0;
      }
    }),
  );

  totalMatches = checks.reduce((a, b) => a + b, 0);
  return { active: totalMatches > 0, matchCount: totalMatches };
}

function parseLastColon(addr: string): string | null {
  const i = addr.lastIndexOf(":");
  if (i < 0) return null;
  return addr.slice(i + 1);
}

function stripPort(addr: string): string | null {
  if (addr.startsWith("[")) {
    const close = addr.indexOf("]");
    if (close > 0) return addr.slice(1, close);
  }
  const i = addr.lastIndexOf(":");
  if (i < 0) return addr;
  return addr.slice(0, i);
}
