/**
 * UFW firewall mutations via the sidecar HTTP API.
 *
 * ufwAllow/ufwDelete each open or close ONE (port, proto) tuple for one IP.
 * The "many" variants take a list of IPs and a list of ports, and open or
 * close the full cartesian product — so a dual-stack rule with both an
 * IPv4 and an IPv6 address hits the sidecar twice per port. Errors are
 * collected per (ip, port, proto) so one failing combination doesn't
 * abort the whole operation.
 */

import { logger } from "../logger";
import { sidecarUfwAllow, sidecarUfwDelete } from "../lib/nsenter";
import type { PortSpec } from "../schemas";

export async function ufwAllow(ip: string, port: string, proto: "tcp" | "udp"): Promise<void> {
  await sidecarUfwAllow(ip, port, proto);
}

export async function ufwDelete(ip: string, port: string, proto: "tcp" | "udp"): Promise<void> {
  await sidecarUfwDelete(ip, port, proto);
}

export interface UfwError {
  ip: string;
  port: string;
  proto: "tcp" | "udp";
  error: string;
}

export async function ufwAllowMany(
  ips: readonly string[],
  ports: readonly PortSpec[],
): Promise<UfwError[]> {
  const errors: UfwError[] = [];
  for (const ip of ips) {
    for (const { port, proto } of ports) {
      try {
        await ufwAllow(ip, port, proto);
      } catch (err) {
        errors.push({ ip, port, proto, error: (err as Error).message });
        logger().warn({ ip, port, proto, err: (err as Error).message }, "ufw allow failed");
      }
    }
  }
  return errors;
}

export async function ufwDeleteMany(
  ips: readonly string[],
  ports: readonly PortSpec[],
): Promise<UfwError[]> {
  const errors: UfwError[] = [];
  for (const ip of ips) {
    for (const { port, proto } of ports) {
      try {
        await ufwDelete(ip, port, proto);
      } catch (err) {
        errors.push({ ip, port, proto, error: (err as Error).message });
        logger().warn({ ip, port, proto, err: (err as Error).message }, "ufw delete failed");
      }
    }
  }
  return errors;
}
