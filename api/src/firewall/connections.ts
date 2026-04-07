/**
 * Kernel connection state queries (ss + conntrack).
 *
 * This is the authoritative source for "is this IP currently playing?"
 * Used by:
 *   - smart-revoke   (don't kick out an active session)
 *   - stats collector (accumulate per-user playtime)
 *   - /api/active-sessions endpoint
 *
 * We batch: one `ss` call + one `conntrack` call regardless of how many
 * users / services are configured. Missing conntrack (UDP) degrades
 * gracefully — TCP games still work.
 */

import { logger } from "../logger";
import { nsenterRun } from "../lib/nsenter";
import type { PortSpec } from "../schemas";

const SS_TIMEOUT_MS = 5_000;
const CONNTRACK_TIMEOUT_MS = 5_000;

export interface LiveConnection {
  srcIp: string;
  dstPort: string;
  proto: "tcp" | "udp";
}

export async function listEstablishedTcp(): Promise<LiveConnection[]> {
  let stdout: string;
  try {
    const res = await nsenterRun(["ss", "-tnH", "state", "established"], SS_TIMEOUT_MS);
    stdout = res.stdout;
  } catch (err) {
    const msg = (err as Error).message;
    if (/no such file|not found/iu.test(msg)) return [];
    throw err;
  }
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
  let stdout: string;
  try {
    const res = await nsenterRun(["conntrack", "-L", "-p", "udp"], CONNTRACK_TIMEOUT_MS);
    stdout = res.stdout;
  } catch {
    // conntrack-tools may not be installed on the host — degrade gracefully
    return [];
  }
  const out: LiveConnection[] = [];
  for (const line of stdout.split("\n")) {
    if (!line.startsWith("udp")) continue;
    const srcMatch = line.match(/src=([\d.]+)/u);
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
