/**
 * UFW firewall mutations via the sidecar HTTP API.
 *
 * The "many" variants fan out across nodes: they take a `portsByNode`
 * map and a `resolveNode` callback, issuing parallel requests to each
 * node's sidecar. In a single-node deployment the map has one key
 * ("local") — semantically identical to the old flat-port API.
 */

import { logger } from "../logger";
import { sidecarUfwAllow, sidecarUfwDelete } from "../lib/nsenter";
import type { NodeConfig, PortSpec } from "../schemas";

export interface UfwError {
  node: string;
  ip: string;
  port: string;
  proto: "tcp" | "udp";
  error: string;
}

export async function ufwAllowMany(
  ips: readonly string[],
  portsByNode: ReadonlyMap<string, readonly PortSpec[]>,
  resolveNode: (nodeId: string) => NodeConfig,
): Promise<UfwError[]> {
  const results = await Promise.allSettled(
    Array.from(portsByNode.entries()).flatMap(([nodeId, ports]) => {
      const node = resolveNode(nodeId);
      return ips.flatMap((ip) =>
        ports.map(async ({ port, proto }) => {
          try {
            await sidecarUfwAllow(node, ip, port, proto);
          } catch (err) {
            logger().warn({ node: nodeId, ip, port, proto, err: (err as Error).message }, "ufw allow failed");
            throw { node: nodeId, ip, port, proto, error: (err as Error).message };
          }
        }),
      );
    }),
  );
  return results
    .filter((r): r is PromiseRejectedResult => r.status === "rejected")
    .map((r) => r.reason as UfwError);
}

export async function ufwDeleteMany(
  ips: readonly string[],
  portsByNode: ReadonlyMap<string, readonly PortSpec[]>,
  resolveNode: (nodeId: string) => NodeConfig,
): Promise<UfwError[]> {
  const results = await Promise.allSettled(
    Array.from(portsByNode.entries()).flatMap(([nodeId, ports]) => {
      const node = resolveNode(nodeId);
      return ips.flatMap((ip) =>
        ports.map(async ({ port, proto }) => {
          try {
            await sidecarUfwDelete(node, ip, port, proto);
          } catch (err) {
            logger().warn({ node: nodeId, ip, port, proto, err: (err as Error).message }, "ufw delete failed");
            throw { node: nodeId, ip, port, proto, error: (err as Error).message };
          }
        }),
      );
    }),
  );
  return results
    .filter((r): r is PromiseRejectedResult => r.status === "rejected")
    .map((r) => r.reason as UfwError);
}
