/**
 * Base adapter for a managed game service.
 *
 * Subclasses implement the methods their game actually supports. The
 * `capabilities` set tells callers (and the frontend) what to render.
 *
 * Required:
 *   - id, name, type           (from registry config)
 *   - container                (docker container name)
 *   - ports                    (array of {port, proto})
 *   - status() → { running: bool, players: [], details: {...} }
 *
 * Optional (gated on capabilities):
 *   - start(), stop(), restart()
 *   - logs(n)
 *   - rcon(cmd)
 *   - whitelistList(), whitelistAdd(player), whitelistRemove(player)
 *   - opAdd(player), opRemove(player)
 *   - backup(), listBackups(), restoreBackup(name)
 *   - listWorlds(), saveCurrentWorld(), changeWorld(name), newWorld(name)
 */

const { exec } = require("child_process");

class BaseAdapter {
  constructor(config) {
    this.id = config.id;
    this.name = config.name || config.id;
    this.type = config.type;
    this.container = config.container;
    this.ports = (config.ports || []).map((p) => ({
      port: String(p.port),
      proto: p.proto,
    }));
    this.config = config;
    this.capabilities = new Set(["lifecycle"]);
  }

  hasCapability(cap) {
    return this.capabilities.has(cap);
  }

  /** Default lifecycle implementation via `docker start/stop`. */
  dockerAction(action) {
    return new Promise((resolve, reject) => {
      const cmd = `docker ${action} ${this.container}`;
      exec(cmd, { timeout: 30000 }, (err, stdout, stderr) => {
        if (err) return reject(new Error(stderr || err.message));
        resolve(stdout.trim());
      });
    });
  }

  start() {
    return this.dockerAction("start");
  }

  stop() {
    return this.dockerAction("stop");
  }

  async restart() {
    try {
      await this.stop();
    } catch {
      // ignore stop failures, container may already be stopped
    }
    return this.start();
  }

  /** Default status: just check if the docker container is running. */
  async status() {
    return new Promise((resolve) => {
      exec(
        `docker inspect --format '{{.State.Running}}' ${this.container}`,
        { timeout: 5000 },
        (err, stdout) => {
          if (err) return resolve({ running: false, players: [], details: {} });
          resolve({
            running: stdout.trim() === "true",
            players: [],
            details: {},
          });
        },
      );
    });
  }

  /** Default logs implementation: docker logs --tail N. */
  logs(lines = 100) {
    return new Promise((resolve, reject) => {
      exec(
        `docker logs --tail ${parseInt(lines, 10)} ${this.container} 2>&1`,
        { timeout: 5000, maxBuffer: 1024 * 1024 },
        (err, stdout) => {
          if (err) return reject(err);
          resolve(stdout.split("\n").filter(Boolean));
        },
      );
    });
  }
}

module.exports = BaseAdapter;
