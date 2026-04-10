/**
 * UFW firewall mutations via the sidecar HTTP API.
 *
 * ufwAllow/ufwDelete each open or close ONE (port, proto) tuple for one IP.
 * The "many" variants iterate and collect errors so a single failing port
 * doesn't abort the whole operation.
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
  port: string;
  proto: "tcp" | "udp";
  error: string;
}

export async function ufwAllowMany(
  ip: string,
  ports: readonly PortSpec[],
): Promise<UfwError[]> {
  const errors: UfwError[] = [];
  for (const { port, proto } of ports) {
    try {
      await ufwAllow(ip, port, proto);
    } catch (err) {
      errors.push({ port, proto, error: (err as Error).message });
      logger().warn({ ip, port, proto, err: (err as Error).message }, "ufw allow failed");
    }
  }
  return errors;
}

export async function ufwDeleteMany(
  ip: string,
  ports: readonly PortSpec[],
): Promise<UfwError[]> {
  const errors: UfwError[] = [];
  for (const { port, proto } of ports) {
    try {
      await ufwDelete(ip, port, proto);
    } catch (err) {
      errors.push({ port, proto, error: (err as Error).message });
      logger().warn({ ip, port, proto, err: (err as Error).message }, "ufw delete failed");
    }
  }
  return errors;
}
