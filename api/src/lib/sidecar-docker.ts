/**
 * Thin HTTP client for Docker operations on remote nodes via the sidecar.
 *
 * Used by registry.dockerExec() for nodes that have no direct dockerHost.
 * Returns a shape compatible with runCmd so callers stay transport-agnostic.
 */

import type { NodeConfig } from "../schemas";

export interface DockerResult {
  stdout: string;
  stderr: string;
}

async function sidecarDockerFetch(
  node: NodeConfig,
  path: string,
  opts: { method?: string; body?: unknown; timeoutMs?: number } = {},
): Promise<Record<string, unknown>> {
  const url = `${node.sidecarUrl}${path}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 10_000);
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
    const data = (await res.json()) as Record<string, unknown>;
    if (!res.ok || data["success"] === false) {
      throw new Error((data["error"] as string) ?? `sidecar ${path}: HTTP ${res.status}`);
    }
    return data;
  } finally {
    clearTimeout(timer);
  }
}

export async function sidecarDockerStart(
  node: NodeConfig,
  container: string,
): Promise<DockerResult> {
  await sidecarDockerFetch(node, "/docker/start", {
    method: "POST",
    body: { container },
    timeoutMs: 10_000,
  });
  return { stdout: container, stderr: "" };
}

export async function sidecarDockerStop(
  node: NodeConfig,
  container: string,
): Promise<DockerResult> {
  await sidecarDockerFetch(node, "/docker/stop", {
    method: "POST",
    body: { container },
    timeoutMs: 10_000,
  });
  return { stdout: container, stderr: "" };
}

export async function sidecarDockerRestart(
  node: NodeConfig,
  container: string,
): Promise<DockerResult> {
  await sidecarDockerFetch(node, "/docker/restart", {
    method: "POST",
    body: { container },
    timeoutMs: 10_000,
  });
  return { stdout: container, stderr: "" };
}

export async function sidecarDockerLogs(
  node: NodeConfig,
  container: string,
  tail: number,
): Promise<string[]> {
  const data = await sidecarDockerFetch(
    node,
    `/docker/logs?container=${encodeURIComponent(container)}&tail=${tail}`,
    { timeoutMs: 15_000 },
  );
  return (data["lines"] as string[]) ?? [];
}

export async function sidecarDockerInspect(
  node: NodeConfig,
  container: string,
): Promise<{ running: boolean; startedAt?: string; status?: string }> {
  const data = await sidecarDockerFetch(
    node,
    `/docker/inspect?container=${encodeURIComponent(container)}`,
    { timeoutMs: 3_000 },
  );
  return {
    running: data["running"] === true,
    startedAt: data["startedAt"] as string | undefined,
    status: data["status"] as string | undefined,
  };
}
