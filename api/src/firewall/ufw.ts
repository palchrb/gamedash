/**
 * UFW firewall mutations via the sidecar HTTP API.
 *
 * The "many" variants fan out across nodes: they take a `portsByNode`
 * map and a `resolveNode` callback, issuing parallel requests to each
 * node's sidecar. In a single-node deployment the map has one key
 * ("local") — semantically identical to the old flat-port API.
 */

import { z } from "zod";
import { config } from "../config";
import { logger } from "../logger";
import { readJson, withLock, writeJson } from "../lib/atomic-file";
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

/**
 * Delete allow rules for every (ip × port) on every node. Failures are
 * logged AND queued in ufw-pending-deletes.json so the periodic sweep
 * retries them — callers drop the rule from firewall-rules.json right
 * after this returns, so without the queue a failed delete would leave
 * an orphaned UFW allow that nothing ever tracks or cleans up again.
 */
export async function ufwDeleteMany(
  ips: readonly string[],
  portsByNode: ReadonlyMap<string, readonly PortSpec[]>,
  resolveNode: (nodeId: string) => NodeConfig,
): Promise<UfwError[]> {
  const results = await Promise.allSettled(
    Array.from(portsByNode.entries()).flatMap(([nodeId, ports]) =>
      ips.flatMap((ip) =>
        ports.map(async ({ port, proto }) => {
          try {
            // resolveNode inside the try: an unknown/removed node must
            // fail this one delete (and get queued), not abort the batch.
            await sidecarUfwDelete(resolveNode(nodeId), ip, port, proto);
          } catch (err) {
            logger().warn({ node: nodeId, ip, port, proto, err: (err as Error).message }, "ufw delete failed");
            throw { node: nodeId, ip, port, proto, error: (err as Error).message };
          }
        }),
      ),
    ),
  );
  const errors = results
    .filter((r): r is PromiseRejectedResult => r.status === "rejected")
    .map((r) => r.reason as UfwError);
  if (errors.length > 0) {
    try {
      await enqueuePendingDeletes(errors);
    } catch (err) {
      logger().error({ err: (err as Error).message, count: errors.length }, "could not queue failed ufw deletes");
    }
  }
  return errors;
}

// ── Pending-delete retry queue ──────────────────────────────────────

const PendingDeleteSchema = z.object({
  node: z.string(),
  ip: z.string(),
  port: z.string(),
  proto: z.enum(["tcp", "udp"]),
  since: z.string(),
  attempts: z.number().int().nonnegative().default(1),
});
const PendingDeletesFileSchema = z.object({
  pending: z.array(PendingDeleteSchema).default([]),
});
type PendingDeletesFile = z.infer<typeof PendingDeletesFileSchema>;

/** Give up on a delete after this long — logged at error level. */
const PENDING_DELETE_MAX_AGE_MS = 7 * 24 * 3_600_000;

function pendingKey(e: { node: string; ip: string; port: string; proto: string }): string {
  return `${e.node}|${e.ip}|${e.port}/${e.proto}`;
}

function pendingFile(): string {
  return config().ufwPendingDeletesFile;
}

async function mutatePending<T>(fn: (draft: PendingDeletesFile) => Promise<T> | T): Promise<T> {
  return withLock(`ufw-pending:${pendingFile()}`, async () => {
    const draft = await readJson(pendingFile(), PendingDeletesFileSchema, { pending: [] });
    const result = await fn(draft);
    await writeJson(pendingFile(), PendingDeletesFileSchema, draft);
    return result;
  });
}

async function enqueuePendingDeletes(errors: readonly UfwError[]): Promise<void> {
  const now = new Date().toISOString();
  await mutatePending((draft) => {
    const existing = new Set(draft.pending.map(pendingKey));
    for (const e of errors) {
      if (existing.has(pendingKey(e))) continue;
      existing.add(pendingKey(e));
      draft.pending.push({ node: e.node, ip: e.ip, port: e.port, proto: e.proto, since: now, attempts: 1 });
    }
  });
}

/**
 * Retry queued deletes. Called from the periodic sweep. Returns counts
 * so the caller can log something useful.
 */
export async function retryPendingDeletes(
  resolveNode: (nodeId: string) => NodeConfig,
): Promise<{ retried: number; cleared: number; abandoned: number; remaining: number }> {
  return mutatePending(async (draft) => {
    if (draft.pending.length === 0) return { retried: 0, cleared: 0, abandoned: 0, remaining: 0 };
    const keep: PendingDeletesFile["pending"] = [];
    let cleared = 0;
    let abandoned = 0;
    for (const p of draft.pending) {
      try {
        await sidecarUfwDelete(resolveNode(p.node), p.ip, p.port, p.proto);
        cleared++;
      } catch (err) {
        if (Date.now() - new Date(p.since).getTime() > PENDING_DELETE_MAX_AGE_MS) {
          abandoned++;
          logger().error(
            { node: p.node, ip: p.ip, port: p.port, proto: p.proto, attempts: p.attempts + 1, err: (err as Error).message },
            "giving up on ufw delete — remove this allow rule manually",
          );
        } else {
          keep.push({ ...p, attempts: p.attempts + 1 });
        }
      }
    }
    const retried = draft.pending.length;
    draft.pending = keep;
    return { retried, cleared, abandoned, remaining: keep.length };
  });
}
