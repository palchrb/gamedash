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
  const results = await Promise.allSettled(
    ips.flatMap((ip) =>
      ports.map(async ({ port, proto }) => {
        try {
          await ufwAllow(ip, port, proto);
        } catch (err) {
          logger().warn({ ip, port, proto, err: (err as Error).message }, "ufw allow failed");
          throw { ip, port, proto, error: (err as Error).message };
        }
      }),
    ),
  );
  return results
    .filter((r): r is PromiseRejectedResult => r.status === "rejected")
    .map((r) => r.reason as UfwError);
}

export async function ufwDeleteMany(
  ips: readonly string[],
  ports: readonly PortSpec[],
): Promise<UfwError[]> {
  const results = await Promise.allSettled(
    ips.flatMap((ip) =>
      ports.map(async ({ port, proto }) => {
        try {
          await ufwDelete(ip, port, proto);
        } catch (err) {
          logger().warn({ ip, port, proto, err: (err as Error).message }, "ufw delete failed");
          throw { ip, port, proto, error: (err as Error).message };
        }
      }),
    ),
  );
  return results
    .filter((r): r is PromiseRejectedResult => r.status === "rejected")
    .map((r) => r.reason as UfwError);
}
