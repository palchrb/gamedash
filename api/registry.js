/**
 * Service registry — loads /mcdata/services.json and instantiates one
 * adapter per service. Adding a new service is a 3-step config change:
 *
 *   1. Add the container to docker-compose.yml (or any compose file
 *      that joins the same docker network as the dashboard).
 *   2. Add a service block to /mcdata/services.json.
 *   3. Restart the dashboard container.
 *
 * services.json schema:
 *   {
 *     "services": [
 *       { "id": "mc1", "name": "...", "type": "minecraft", "container": "...",
 *         "rcon": { "host": "mc1", "port": 25575, "passwordEnv": "RCON_PASSWORD_MC1" },
 *         "ports": [{"port":"25565","proto":"tcp"},...],
 *         "dataDir": "/mcdata/mc1",
 *         "logFile": "/mcdata/mc1/logs/latest.log"
 *       }
 *     ]
 *   }
 *
 * If services.json is missing on first boot, a default file is auto-generated
 * from environment variables (RCON_HOST, RCON_PORT, RCON_PASSWORD, MC_CONTAINER,
 * MC_LOG_FILE) so existing single-MC deployments keep working without manual
 * migration.
 */

const fs = require("fs-extra");
const path = require("path");
const MinecraftAdapter = require("./services/minecraft");
const GenericAdapter = require("./services/generic");

const SERVICES_FILE = process.env.SERVICES_FILE || "/mcdata/services.json";
const DEFAULT_SERVICE_ID = process.env.DEFAULT_SERVICE_ID || "mc1";

const ADAPTERS = {
  minecraft: MinecraftAdapter,
  generic: GenericAdapter,
};

class Registry {
  constructor() {
    this.services = new Map();
    this.configList = [];
  }

  /** Auto-generate services.json from legacy env vars on first boot. */
  static seedDefaultConfig() {
    const config = {
      services: [
        {
          id: "mc1",
          name: "Minecraft",
          type: "minecraft",
          container: process.env.MC_CONTAINER || "minecraft-mc-1",
          rcon: {
            host: process.env.RCON_HOST || "mc",
            port: parseInt(process.env.RCON_PORT, 10) || 25575,
            passwordEnv: "RCON_PASSWORD",
          },
          ports: [
            { port: "25565", proto: "tcp" },
            { port: "19132", proto: "udp" },
            { port: "24454", proto: "udp" },
          ],
          dataDir: "/mcdata",
          logFile: process.env.MC_LOG_FILE || "/mcdata/logs/latest.log",
        },
      ],
    };
    fs.writeFileSync(SERVICES_FILE, JSON.stringify(config, null, 2));
    console.log(`registry: seeded default services.json at ${SERVICES_FILE}`);
    return config;
  }

  load() {
    let raw;
    if (!fs.existsSync(SERVICES_FILE)) {
      raw = Registry.seedDefaultConfig();
    } else {
      try {
        raw = JSON.parse(fs.readFileSync(SERVICES_FILE, "utf8"));
      } catch (err) {
        console.error("registry: failed to parse services.json:", err.message);
        raw = { services: [] };
      }
    }

    this.configList = raw.services || [];
    this.services.clear();

    for (const cfg of this.configList) {
      try {
        const AdapterClass = ADAPTERS[cfg.type] || GenericAdapter;
        const adapter = new AdapterClass(cfg);
        this.services.set(cfg.id, adapter);
        console.log(`registry: loaded service ${cfg.id} (${cfg.type})`);
      } catch (err) {
        console.error(`registry: failed to instantiate ${cfg.id}:`, err.message);
      }
    }

    return this;
  }

  list() {
    // Return shallow descriptors safe to send to clients (no secrets)
    return Array.from(this.services.values()).map((s) => ({
      id: s.id,
      name: s.name,
      type: s.type,
      container: s.container,
      ports: s.ports,
      capabilities: Array.from(s.capabilities),
    }));
  }

  /** Get raw adapter instance, or null if not found. */
  get(id) {
    return this.services.get(id) || null;
  }

  /** Get the default adapter (used by legacy /api/* routes). */
  getDefault() {
    return this.services.get(DEFAULT_SERVICE_ID) || this.services.values().next().value || null;
  }

  /** Get all configured ports for a list of service ids (or all services). */
  collectPorts(ids) {
    const wanted = ids && ids.length ? new Set(ids) : null;
    const seen = new Set();
    const out = [];
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

  /** Build a `services` array for a firewall rule (one entry per service id). */
  buildRuleServices(ids) {
    const wanted = ids && ids.length ? new Set(ids) : null;
    const out = [];
    for (const svc of this.services.values()) {
      if (wanted && !wanted.has(svc.id)) continue;
      out.push({
        id: svc.id,
        ports: svc.ports.map((p) => ({ port: p.port, proto: p.proto })),
      });
    }
    return out;
  }
}

module.exports = {
  Registry,
  SERVICES_FILE,
  DEFAULT_SERVICE_ID,
};
