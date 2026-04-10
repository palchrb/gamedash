/**
 * UFW sidecar client — replaces the old nsenter-via-docker-exec approach
 * with HTTP calls to the dedicated sidecar API.
 *
 * The sidecar runs as a privileged container with pid:host and exposes
 * a strict HTTP API for firewall mutations and connection queries.
 * The dashboard no longer needs the docker socket for these operations.
 */

import { config } from "../config";

export interface SidecarResponse {
  success: boolean;
  error?: string;
  raw?: string;
}

function baseUrl(): string {
  return config().UFW_SIDECAR_URL;
}

async function sidecarFetch(
  path: string,
  opts: { method?: string; body?: unknown; timeoutMs?: number } = {},
): Promise<SidecarResponse> {
  const url = `${baseUrl()}${path}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 15_000);
  try {
    const res = await fetch(url, {
      method: opts.method ?? "GET",
      signal: controller.signal,
      ...(opts.body
        ? {
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(opts.body),
          }
        : {}),
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
  ip: string,
  port: string,
  proto: "tcp" | "udp",
): Promise<void> {
  await sidecarFetch("/ufw/allow", {
    method: "POST",
    body: { ip, port, proto },
  });
}

export async function sidecarUfwDelete(
  ip: string,
  port: string,
  proto: "tcp" | "udp",
): Promise<void> {
  await sidecarFetch("/ufw/delete", {
    method: "POST",
    body: { ip, port, proto },
  });
}

export async function sidecarTcpConnections(): Promise<string> {
  const res = await sidecarFetch("/connections/tcp", { timeoutMs: 5_000 });
  return res.raw ?? "";
}

export async function sidecarUdpConnections(): Promise<string> {
  const res = await sidecarFetch("/connections/udp", { timeoutMs: 5_000 });
  return res.raw ?? "";
}
