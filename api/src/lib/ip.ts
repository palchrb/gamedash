/**
 * IP validation + classification.
 *
 * isValidPublicIPv4 matches the original implementation: strict IPv4 with
 * dotted decimal, no leading zeros, and rejects private / loopback / link
 * local / CGNAT-ish ranges. Callers rely on this rejecting RFC1918 so we
 * never open a firewall rule for an internal address by mistake.
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

export function ipToUint32(ip: string): number {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4) return 0;
  return (
    (((parts[0]! << 24) | (parts[1]! << 16) | (parts[2]! << 8) | parts[3]!) >>> 0)
  );
}

export function isInIgnoredRange(ip: string, config: Pick<Config, "knockIgnoreRanges">): boolean {
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
