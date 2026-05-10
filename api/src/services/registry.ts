/**
 * Service registry — loads services.json and instantiates one adapter
 * per service. No auto-seeding: services.json MUST exist. If it is
 * missing the server refuses to start with a clear error message.
 *
 * Adding a service is a 3-step operation:
 *   1. Add the container block to your docker-compose (same docker
 *      network as the dashboard).
 *   2. Add a block to /data/services.json.
 *   3. Restart the dashboard container.
 */

import { config } from "../config";
import { runCmd } from "../lib/exec";
import { logger } from "../logger";
import { pathExists, readJson } from "../lib/atomic-file";
import {
  sidecarDockerStart,
  sidecarDockerStop,
  sidecarDockerRestart,
  sidecarDockerLogs,
  sidecarDockerInspect,
} from "../lib/sidecar-docker";
import {
  ServicesFileSchema,
  type NodeConfig,
  type PortSpec,
  type RuleService,
  type ServiceConfig,
} from "../schemas";
import { GenericAdapter } from "./generic";
import { ImpostorAdapter } from "./impostor";
import { MinecraftAdapter } from "./minecraft";
import { TShockAdapter } from "./tshock";
import type { ServiceAdapter, ServiceDescriptor } from "./types";

export type { NodeConfig };

export class Registry {
  readonly services = new Map<string, ServiceAdapter>();
  readonly nodes = new Map<string, NodeConfig>();

  async load(): Promise<this> {
    const file = config().servicesFile;
    if (!(await pathExists(file))) {
      throw new Error(
        `services.json not found at ${file} — see README for a sample configuration`,
      );
    }
    const data = await readJson(file, ServicesFileSchema, { services: [] });

    // ── Build nodes map ────────────────────────────────────────────
    this.nodes.clear();
    if (data.nodes) {
      for (const [id, nodeCfg] of Object.entries(data.nodes)) {
        this.nodes.set(id, nodeCfg);
      }
    }
    if (!this.nodes.has("local")) {
      this.nodes.set("local", {
        sidecarUrl: config().UFW_SIDECAR_URL,
        sidecarToken: config().UFW_SIDECAR_TOKEN,
        dockerHost: process.env["DOCKER_HOST"],
      });
    }

    // ── Load services ──────────────────────────────────────────────
    this.services.clear();
    for (const cfg of data.services) {
      const nodeId = cfg.node ?? "local";
      if (!this.nodes.has(nodeId)) {
        logger().error(
          { id: cfg.id, node: nodeId },
          `service references unknown node "${nodeId}" — skipping`,
        );
        continue;
      }
      this.validateRemoteServiceUrls(cfg, nodeId);
      try {
        let adapter: ServiceAdapter;
        switch (cfg.type) {
          case "minecraft":
            adapter = new MinecraftAdapter(cfg);
            break;
          case "impostor":
            adapter = new ImpostorAdapter(cfg);
            break;
          case "tshock":
            adapter = new TShockAdapter(cfg);
            break;
          default:
            adapter = new GenericAdapter(cfg);
            break;
        }
        this.services.set(cfg.id, adapter);
        logger().info({ id: cfg.id, type: cfg.type, node: nodeId }, "service loaded");
      } catch (err) {
        logger().error(
          { id: cfg.id, err: (err as Error).message },
          "failed to load service",
        );
      }
    }
    if (this.services.size === 0) {
      throw new Error("No services configured in services.json");
    }

    // Validate remote nodes have sidecar tokens
    for (const [id, nodeCfg] of this.nodes) {
      if (id !== "local" && !nodeCfg.sidecarToken) {
        throw new Error(
          `Node "${id}" is missing sidecarToken — remote nodes require a token for authentication`,
        );
      }
    }

    return this;
  }

  private validateRemoteServiceUrls(cfg: ServiceConfig, nodeId: string): void {
    if (nodeId === "local") return;
    const missing: string[] = [];
    if (cfg.type === "minecraft" && !cfg.rcon?.host) missing.push("rcon.host");
    if (cfg.type === "impostor" && !cfg.impostorAdminApiUrl) missing.push("impostorAdminApiUrl");
    if (cfg.type === "tshock" && !cfg.tshockApiUrl) missing.push("tshockApiUrl");
    if (missing.length > 0) {
      throw new Error(
        `Service "${cfg.id}" is on node "${nodeId}" but is missing ${missing.join(", ")}. ` +
        `Remote services must specify mesh URLs explicitly.`,
      );
    }
  }

  list(): ServiceDescriptor[] {
    return Array.from(this.services.values()).map((s) => s.describe());
  }

  get(id: string): ServiceAdapter | null {
    return this.services.get(id) ?? null;
  }

  getDefault(): ServiceAdapter | null {
    const preferred = config().DEFAULT_SERVICE_ID;
    return this.services.get(preferred) ?? this.services.values().next().value ?? null;
  }

  resolveNode(nodeId: string): NodeConfig {
    const node = this.nodes.get(nodeId);
    if (!node) throw new Error(`Unknown node "${nodeId}"`);
    return node;
  }

  getNodeForService(id: string): string {
    const svc = this.services.get(id);
    if (!svc) throw new Error(`Unknown service "${id}"`);
    return svc.nodeId;
  }

  listNodeIds(): string[] {
    return Array.from(this.nodes.keys());
  }

  collectPortsByNode(ids?: readonly string[] | null): Map<string, PortSpec[]> {
    const wanted = ids && ids.length ? new Set(ids) : null;
    const byNode = new Map<string, PortSpec[]>();
    for (const svc of this.services.values()) {
      if (wanted && !wanted.has(svc.id)) continue;
      const nodeId = svc.nodeId;
      let list = byNode.get(nodeId);
      if (!list) {
        list = [];
        byNode.set(nodeId, list);
      }
      const seen = new Set(list.map((p) => `${p.port}/${p.proto}`));
      for (const p of svc.ports) {
        const key = `${p.port}/${p.proto}`;
        if (!seen.has(key)) {
          seen.add(key);
          list.push({ port: p.port, proto: p.proto });
        }
      }
    }
    return byNode;
  }

  buildRuleServicesByNode(ids?: readonly string[] | null): Map<string, RuleService[]> {
    const wanted = ids && ids.length ? new Set(ids) : null;
    const byNode = new Map<string, RuleService[]>();
    for (const svc of this.services.values()) {
      if (wanted && !wanted.has(svc.id)) continue;
      const nodeId = svc.nodeId;
      let list = byNode.get(nodeId);
      if (!list) {
        list = [];
        byNode.set(nodeId, list);
      }
      list.push({
        id: svc.id,
        ports: svc.ports.map((p) => ({ port: p.port, proto: p.proto })),
        node: nodeId,
      });
    }
    return byNode;
  }

  /** Collected, deduplicated list of ports for the given service ids (or all). */
  collectPorts(ids?: readonly string[] | null): PortSpec[] {
    const wanted = ids && ids.length ? new Set(ids) : null;
    const seen = new Set<string>();
    const out: PortSpec[] = [];
    for (const svc of this.services.values()) {
      if (wanted && !wanted.has(svc.id)) continue;
      for (const p of svc.ports) {
        const key = `${p.port}/${p.proto}`;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push({ port: p.port, proto: p.proto });
      }
    }
    return out;
  }

  /** Build the per-service entries for a firewall rule. */
  buildRuleServices(ids?: readonly string[] | null): RuleService[] {
    const wanted = ids && ids.length ? new Set(ids) : null;
    const out: RuleService[] = [];
    for (const svc of this.services.values()) {
      if (wanted && !wanted.has(svc.id)) continue;
      out.push({
        id: svc.id,
        ports: svc.ports.map((p) => ({ port: p.port, proto: p.proto })),
        node: svc.nodeId,
      });
    }
    return out;
  }

  /**
   * Route Docker operations to the right transport. If the node has
   * dockerHost set, use the docker CLI directly (local node). Otherwise
   * go via the sidecar HTTP API (remote node).
   */
  async dockerAction(
    nodeId: string,
    action: "start" | "stop" | "restart",
    container: string,
    opts?: { timeoutMs?: number },
  ): Promise<{ stdout: string; stderr: string }> {
    const node = this.resolveNode(nodeId);
    if (node.dockerHost) {
      return runCmd("docker", [action, container], {
        timeoutMs: opts?.timeoutMs ?? 30_000,
        env: { ...process.env, DOCKER_HOST: node.dockerHost },
      });
    }
    switch (action) {
      case "start":
        return sidecarDockerStart(node, container);
      case "stop":
        return sidecarDockerStop(node, container);
      case "restart":
        return sidecarDockerRestart(node, container);
    }
  }

  async dockerInspect(
    nodeId: string,
    container: string,
  ): Promise<{ running: boolean }> {
    const node = this.resolveNode(nodeId);
    if (node.dockerHost) {
      const res = await runCmd(
        "docker",
        ["inspect", "--format", "{{.State.Running}}", container],
        { timeoutMs: 5_000, env: { ...process.env, DOCKER_HOST: node.dockerHost } },
      );
      return { running: res.stdout.trim() === "true" };
    }
    return sidecarDockerInspect(node, container);
  }

  async dockerLogs(
    nodeId: string,
    container: string,
    lines: number,
  ): Promise<string[]> {
    const node = this.resolveNode(nodeId);
    if (node.dockerHost) {
      const res = await runCmd(
        "docker",
        ["logs", "--tail", String(Math.max(1, Math.floor(lines))), container],
        { timeoutMs: 5_000, env: { ...process.env, DOCKER_HOST: node.dockerHost } },
      );
      return (res.stdout + res.stderr).split("\n").filter(Boolean);
    }
    return sidecarDockerLogs(node, container, lines);
  }

  async dispose(): Promise<void> {
    for (const svc of this.services.values()) {
      if (svc.dispose) {
        try {
          await svc.dispose();
        } catch (err) {
          logger().warn(
            { id: svc.id, err: (err as Error).message },
            "service dispose failed",
          );
        }
      }
    }
    this.services.clear();
  }
}

// Singleton used by routes
let _registry: Registry | null = null;

export function registry(): Registry {
  if (!_registry) throw new Error("registry not initialised");
  return _registry;
}

export async function initRegistry(): Promise<Registry> {
  _registry = await new Registry().load();
  return _registry;
}

export async function disposeRegistry(): Promise<void> {
  if (!_registry) return;
  await _registry.dispose();
  _registry = null;
}

// Helper for tests
export function setRegistryForTests(r: Registry | null): void {
  _registry = r;
}

