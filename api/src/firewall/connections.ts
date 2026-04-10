/**
 * Kernel connection state queries via the sidecar HTTP API.
 *
 * This is the authoritative source for "is this IP currently playing?"
 * Used by:
 *   - smart-revoke   (don't kick out an active session)
 *   - stats collector (accumulate per-user playtime)
 *   - /api/active-sessions endpoint
 *
 * We batch: one sidecar call for TCP + one for UDP regardless of how many
 * users / services are configured. Missing conntrack (UDP) degrades
 * gracefully — TCP games still work.
 */

import { logger } from "../logger";
import { sidecarTcpConnections, sidecarUdpConnections } from "../lib/nsenter";
import type { PortSpec } from "../schemas";

export interface LiveConnection {
  srcIp: string;
  dstPort: string;
  proto: "tcp" | "udp";
}

export async function listEstablishedTcp(): Promise<LiveConnection[]> {
  const stdout = await sidecarTcpConnections();
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
    out.push({ srcIp: peerHost, dstPort: localPort, proto: "tcp" });
  }
  return out;
}

export async function listUdpFlows(): Promise<LiveConnection[]> {
  const stdout = await sidecarUdpConnections();
  if (!stdout) return [];
  const out: LiveConnection[] = [];
  for (const line of stdout.split("\n")) {
    // Accept both IPv4 (`udp 17 29 src=1.2.3.4 ...`) and IPv6
    // (`ipv6 10 udp 17 29 src=2001:db8::1 ...`) conntrack output.
    // A plain `startsWith("udp")` would drop all IPv6 flows.
    if (!/(^|\s)udp(\s|$)/u.test(line)) continue;
    // `src=` value runs until the next whitespace — covers both dotted
    // IPv4 and colon-hex IPv6. Non-global .match() returns the first
    // occurrence, which is the original (client→server) tuple.
    const srcMatch = line.match(/src=(\S+)/u);
    const dportMatch = line.match(/dport=(\d+)/u);
    if (!srcMatch || !dportMatch) continue;
    out.push({ srcIp: srcMatch[1]!, dstPort: dportMatch[1]!, proto: "udp" });
  }
  return out;
}

export async function listAllConnections(
  filterPorts?: readonly PortSpec[],
): Promise<LiveConnection[]> {
  const [tcp, udp] = await Promise.all([
    listEstablishedTcp().catch((err: Error) => {
      logger().warn({ err: err.message }, "ss query failed");
      return [] as LiveConnection[];
    }),
    listUdpFlows().catch((err: Error) => {
      logger().warn({ err: err.message }, "conntrack query failed");
      return [] as LiveConnection[];
    }),
  ]);
  const all = [...tcp, ...udp];
  if (!filterPorts || filterPorts.length === 0) return all;
  const wanted = new Set(filterPorts.map((p) => `${p.port}/${p.proto}`));
  return all.filter((c) => wanted.has(`${c.dstPort}/${c.proto}`));
}

export interface ActiveCheckResult {
  active: boolean;
  matchCount: number;
}

export async function isIpActiveOnPorts(
  ip: string,
  ports: readonly PortSpec[],
): Promise<ActiveCheckResult> {
  if (!ip || ports.length === 0) return { active: false, matchCount: 0 };
  const conns = await listAllConnections(ports);
  const matches = conns.filter((c) => c.srcIp === ip);
  return { active: matches.length > 0, matchCount: matches.length };
}

/**
 * Multi-IP variant: returns active if *any* of the given IPs has a live
 * connection on the given ports. Used by smart-revoke on dual-stack
 * rules (v4 + v6) — if the game client is still connected over either
 * protocol, we shouldn't nuke the whole rule.
 */
export async function isAnyIpActiveOnPorts(
  ips: readonly string[],
  ports: readonly PortSpec[],
): Promise<ActiveCheckResult> {
  if (ips.length === 0 || ports.length === 0) {
    return { active: false, matchCount: 0 };
  }
  const conns = await listAllConnections(ports);
  const set = new Set(ips);
  const matches = conns.filter((c) => set.has(c.srcIp));
  return { active: matches.length > 0, matchCount: matches.length };
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
