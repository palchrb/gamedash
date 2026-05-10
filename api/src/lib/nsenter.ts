/**
 * UFW sidecar client — HTTP calls to a per-node sidecar API for
 * firewall mutations and connection queries.
 *
 * Every export takes an explicit NodeConfig so the caller controls
 * which node the request targets. No global config dependency.
 */

import type { NodeConfig } from "../schemas";

export interface SidecarResponse {
  success: boolean;
  error?: string;
  raw?: string;
}

async function sidecarFetch(
  node: NodeConfig,
  path: string,
  opts: { method?: string; body?: unknown; timeoutMs?: number } = {},
): Promise<SidecarResponse> {
  const url = `${node.sidecarUrl}${path}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 15_000);
  try {
    const headers: Record<string, string> = {};
    if (node.sidecarToken) headers["x-sidecar-token"] = node.sidecarToken;
    if (opts.body) headers["Content-Type"] = "application/json";
    const res = await fetch(url, {
      method: opts.method ?? "GET",
      signal: controller.signal,
      headers,
      ...(opts.body ? { body: JSON.stringify(opts.body) } : {}),
    });
    const data = (await res.json()) as SidecarResponse;
    if (!res.ok || !data.success) {
      throw new Error(data.error ?? `sidecar ${path}: HTTP ${res.status}`);
    }
    return data;
  } finally {
    clearTimeout(timer);
  }
}

// ── Public API (consumed by firewall/ufw.ts and firewall/connections.ts) ──

export async function sidecarUfwAllow(
  node: NodeConfig,
  ip: string,
  port: string,
  proto: "tcp" | "udp",
): Promise<void> {
  await sidecarFetch(node, "/ufw/allow", {
    method: "POST",
    body: { ip, port, proto },
    timeoutMs: 5_000,
  });
}

export async function sidecarUfwDelete(
  node: NodeConfig,
  ip: string,
  port: string,
  proto: "tcp" | "udp",
): Promise<void> {
  await sidecarFetch(node, "/ufw/delete", {
    method: "POST",
    body: { ip, port, proto },
    timeoutMs: 5_000,
  });
}

export async function sidecarTcpConnections(node: NodeConfig): Promise<string> {
  const res = await sidecarFetch(node, "/connections/tcp", { timeoutMs: 3_000 });
  return res.raw ?? "";
}

export async function sidecarUdpConnections(node: NodeConfig): Promise<string> {
  const res = await sidecarFetch(node, "/connections/udp", { timeoutMs: 3_000 });
  return res.raw ?? "";
}
