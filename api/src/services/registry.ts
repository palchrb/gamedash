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
import { logger } from "../logger";
import { pathExists, readJson } from "../lib/atomic-file";
import { ServicesFileSchema, type PortSpec, type RuleService } from "../schemas";
import { GenericAdapter } from "./generic";
import { MinecraftAdapter } from "./minecraft";
import type { ServiceAdapter, ServiceDescriptor } from "./types";

export class Registry {
  readonly services = new Map<string, ServiceAdapter>();

  async load(): Promise<this> {
    const file = config().servicesFile;
    if (!(await pathExists(file))) {
      throw new Error(
        `services.json not found at ${file} — see README for a sample configuration`,
      );
    }
    const data = await readJson(file, ServicesFileSchema, { services: [] });
    this.services.clear();
    for (const cfg of data.services) {
      try {
        const adapter: ServiceAdapter =
          cfg.type === "minecraft" ? new MinecraftAdapter(cfg) : new GenericAdapter(cfg);
        this.services.set(cfg.id, adapter);
        logger().info({ id: cfg.id, type: cfg.type }, "service loaded");
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
    return this;
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
      });
    }
    return out;
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

