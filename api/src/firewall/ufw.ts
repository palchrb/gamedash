/**
 * UFW firewall mutations via the ufw-agent sidecar.
 *
 * All operations go through `docker exec ufw-agent nsenter -t 1 ... ufw ...`
 * so we run the real host ufw with privileged access without having to run
 * the dashboard container itself as privileged.
 *
 * ufwAllow/ufwDelete each open or close ONE (port, proto) tuple for one IP.
 * The "many" variants iterate and collect errors so a single failing port
 * doesn't abort the whole operation.
 */

import { logger } from "../logger";
import { nsenterRun } from "../lib/nsenter";
import type { PortSpec } from "../schemas";

const UFW_CMD_TIMEOUT_MS = 15_000;

export async function ufwAllow(ip: string, port: string, proto: "tcp" | "udp"): Promise<void> {
  await nsenterRun(
    [
      "ufw",
      "route",
      "allow",
      "from",
      ip,
      "to",
      "any",
      "port",
      port,
      "proto",
      proto,
    ],
    UFW_CMD_TIMEOUT_MS,
  );
}

export async function ufwDelete(ip: string, port: string, proto: "tcp" | "udp"): Promise<void> {
  await nsenterRun(
    [
      "ufw",
      "route",
      "delete",
      "allow",
      "from",
      ip,
      "to",
      "any",
      "port",
      port,
      "proto",
      proto,
    ],
    UFW_CMD_TIMEOUT_MS,
  );
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
