/**
 * Base service adapter — common docker-exec lifecycle for any container.
 *
 * Subclasses (minecraft, generic) override methods for their specific
 * semantics. Default implementations cover start/stop/restart/status/logs
 * via the docker CLI available in the dashboard container.
 */

import { runCmd } from "../lib/exec";
import type {
  Capability,
  MapProxyTarget,
  ServiceAdapter,
  ServiceDescriptor,
  ServiceStatus,
} from "./types";
import type { PortSpec, ServiceConfig } from "../schemas";

const DOCKER_CMD_TIMEOUT_MS = 30_000;
const DOCKER_STATUS_TIMEOUT_MS = 5_000;

export class BaseAdapter implements ServiceAdapter {
  readonly id: string;
  readonly name: string;
  readonly type: string;
  readonly container: string;
  readonly ports: PortSpec[];
  readonly mapUrl?: string;
  readonly mapProxy?: MapProxyTarget;
  readonly connectAddress?: string;
  readonly connectGuideUrl?: string;
  readonly capabilities: Set<Capability>;
  protected readonly config: ServiceConfig;

  constructor(config: ServiceConfig) {
    this.id = config.id;
    this.name = config.name;
    this.type = config.type;
    this.container = config.container;
    this.ports = config.ports.map((p) => ({ port: String(p.port), proto: p.proto }));
    if (config.mapUrl) this.mapUrl = config.mapUrl;
    if (config.mapProxy) {
      this.mapProxy = {
        host: config.mapProxy.host,
        port: config.mapProxy.port,
        scheme: config.mapProxy.scheme,
      };
    }
    if (config.connectAddress) this.connectAddress = config.connectAddress;
    if (config.connectGuideUrl) this.connectGuideUrl = config.connectGuideUrl;
    this.config = config;
    this.capabilities = new Set<Capability>(["lifecycle"]);
  }

  hasCapability(cap: Capability): boolean {
    return this.capabilities.has(cap);
  }

  describe(): ServiceDescriptor {
    return {
      id: this.id,
      name: this.name,
      type: this.type,
      container: this.container,
      ports: this.ports,
      capabilities: Array.from(this.capabilities),
    };
  }

  protected async dockerAction(action: "start" | "stop" | "restart"): Promise<string> {
    const res = await runCmd("docker", [action, this.container], {
      timeoutMs: DOCKER_CMD_TIMEOUT_MS,
    });
    return res.stdout.trim();
  }

  async start(): Promise<string> {
    await this.dockerAction("start");
    return "starting";
  }

  async stop(): Promise<string> {
    await this.dockerAction("stop");
    return "stopping";
  }

  async restart(): Promise<string> {
    try {
      await this.dockerAction("stop");
    } catch {
      // ignore — container may already be stopped
    }
    await this.dockerAction("start");
    return "restarting";
  }

  async status(): Promise<ServiceStatus> {
    try {
      const res = await runCmd(
        "docker",
        ["inspect", "--format", "{{.State.Running}}", this.container],
        { timeoutMs: DOCKER_STATUS_TIMEOUT_MS },
      );
      return {
        running: res.stdout.trim() === "true",
        players: [],
        details: {},
      };
    } catch {
      return { running: false, players: [], details: {} };
    }
  }

  async logs(lines = 100): Promise<string[]> {
    try {
      const res = await runCmd(
        "docker",
        ["logs", "--tail", String(Math.max(1, Math.floor(lines))), this.container],
        { timeoutMs: DOCKER_STATUS_TIMEOUT_MS },
      );
      return (res.stdout + res.stderr).split("\n").filter(Boolean);
    } catch {
      return [];
    }
  }
}
