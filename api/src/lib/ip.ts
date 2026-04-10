/**
 * IP validation + classification.
 *
 * isValidPublicIPv4 matches the original implementation: strict IPv4 with
 * dotted decimal, no leading zeros, and rejects private / loopback / link
 * local / CGNAT-ish ranges. Callers rely on this rejecting RFC1918 so we
 * never open a firewall rule for an internal address by mistake.
 *
 * isValidPublicIPv6 accepts global-unicast IPv6 addresses (2000::/3) and
 * rejects loopback, link-local, ULA, and IPv4-mapped ranges.
 *
 * isValidPublicIP accepts either format.
 */

import type { Request } from "express";
import type { Config } from "../config";

export function isValidPublicIPv4(ip: unknown): ip is string {
  if (typeof ip !== "string") return false;
  const match = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/u);
  if (!match) return false;
  const parts = [match[1]!, match[2]!, match[3]!, match[4]!];
  const octets = parts.map(Number);
  if (octets.some((o) => o > 255)) return false;
  if (parts.some((s) => s.length > 1 && s.startsWith("0"))) return false;
  const [a, b] = octets as [number, number, number, number];
  if (a === 0) return false;
  if (a === 10) return false;
  if (a === 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a >= 224) return false;
  return true;
}

/**
 * Parse an IPv6 string into 8 × 16-bit groups. Returns null on invalid input.
 */
function parseIPv6(ip: string): number[] | null {
  // Strip zone ID (%eth0 etc.)
  const bare = ip.replace(/%.*$/u, "");
  const halves = bare.split("::");
  if (halves.length > 2) return null;

  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves[1] !== undefined ? (halves[1] ? halves[1].split(":") : []) : [];

  if (left.length + right.length > 8) return null;
  const fill = 8 - left.length - right.length;
  if (halves.length === 1 && left.length !== 8) return null;
  if (halves.length === 2 && fill < 0) return null;

  const groups = [...left, ...Array(fill).fill("0") as string[], ...right];
  if (groups.length !== 8) return null;
  const nums: number[] = [];
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/u.test(g)) return null;
    nums.push(parseInt(g, 16));
  }
  return nums;
}

export function isValidPublicIPv6(ip: unknown): ip is string {
  if (typeof ip !== "string") return false;
  const groups = parseIPv6(ip);
  if (!groups) return false;

  // Loopback ::1
  if (groups.slice(0, 7).every((g) => g === 0) && groups[7] === 1) return false;
  // Unspecified ::
  if (groups.every((g) => g === 0)) return false;
  // Link-local fe80::/10
  if ((groups[0]! & 0xffc0) === 0xfe80) return false;
  // Unique Local fc00::/7
  if ((groups[0]! & 0xfe00) === 0xfc00) return false;
  // IPv4-mapped ::ffff:0:0/96
  if (groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff) return false;
  // Must be global unicast (2000::/3)
  if ((groups[0]! & 0xe000) !== 0x2000) return false;

  return true;
}

export function isValidPublicIP(ip: unknown): ip is string {
  return isValidPublicIPv4(ip) || isValidPublicIPv6(ip);
}

export function ipToUint32(ip: string): number {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4) return 0;
  return (
    (((parts[0]! << 24) | (parts[1]! << 16) | (parts[2]! << 8) | parts[3]!) >>> 0)
  );
}

export function isInIgnoredRange(ip: string, config: Pick<Config, "knockIgnoreRanges">): boolean {
  // IPv6 addresses are never in the ignored ranges (which are IPv4 CIDRs)
  if (ip.includes(":")) return false;

  // Accept any dotted-quad here — we want CGNAT / tailscale / link-local
  // ranges to match even though they are not "public IPv4" per se.
  const parts = ip.split(".");
  if (parts.length !== 4) return false;
  if (parts.some((p) => Number.isNaN(Number(p)))) return false;
  const ip32 = ipToUint32(ip);
  return config.knockIgnoreRanges.some((r) => (ip32 & r.mask) === (r.ip32 & r.mask));
}

/**
 * Extract the client IP from a request, honouring `X-Forwarded-For` when
 * Express `trust proxy` is configured. We use `req.ip` (Express's trusted
 * parser) instead of reading the header ourselves so spoofing via an
 * untrusted hop cannot bypass admin auth.
 */
export function clientIp(req: Request): string {
  const raw = req.ip ?? req.socket.remoteAddress ?? "";
  return raw.replace(/^::ffff:/u, "").trim();
}
