/**
 * Minecraft adapter — wraps the original `server.js` MC logic per-instance.
 *
 * Each instance has its own RCON client, log file, data dir and backup pool.
 * Multiple Minecraft instances can run side-by-side; each one is configured
 * via a registry block in services.json.
 *
 * Required config fields:
 *   - id, name, container
 *   - ports                (array of {port,proto})
 *   - rcon: { host, port, passwordEnv | password }
 *   - dataDir              (root of the MC instance's persistent data)
 *
 * Optional:
 *   - logFile              (path inside dataDir, default "logs/latest.log")
 *   - backupsDir           (default "<dataDir>/backups")
 *   - worldsDir            (default "<dataDir>/worlds")
 *   - activeWorldDir       (default "<dataDir>/world")
 *   - currentWorldFile     (default "<dataDir>/current-world.txt")
 */

const fs = require("fs-extra");
const path = require("path");
const { exec } = require("child_process");
const { Rcon } = require("rcon-client");
const BaseAdapter = require("./base");

class MinecraftAdapter extends BaseAdapter {
  constructor(config) {
    super(config);
    this.capabilities = new Set([
      "lifecycle",
      "logs",
      "rcon",
      "whitelist",
      "op",
      "backup",
      "worlds",
      "players",
    ]);
    this.rconConfig = {
      host: config.rcon?.host || config.container,
      port: parseInt(config.rcon?.port, 10) || 25575,
      password:
        config.rcon?.password ||
        (config.rcon?.passwordEnv && process.env[config.rcon.passwordEnv]) ||
        process.env.RCON_PASSWORD ||
        "changeme",
    };
    this.dataDir = config.dataDir || "/mcdata";
    this.logFile = config.logFile
      ? path.isAbsolute(config.logFile)
        ? config.logFile
        : path.join(this.dataDir, config.logFile)
      : path.join(this.dataDir, "logs", "latest.log");
    this.backupsDir = config.backupsDir || path.join(this.dataDir, "backups");
    this.worldsDir = config.worldsDir || path.join(this.dataDir, "worlds");
    this.activeWorldDir = config.activeWorldDir || path.join(this.dataDir, "world");
    this.currentWorldFile =
      config.currentWorldFile || path.join(this.dataDir, "current-world.txt");

    fs.ensureDirSync(this.backupsDir);
    fs.ensureDirSync(this.worldsDir);

    this.rcon = null;
    this.rconConnected = false;
    this.rconConnecting = false;
    this._scheduleConnect(40000);
  }

  // ---- RCON management ----------------------------------------------------

  async _connectRcon() {
    if (this.rconConnecting || this.rconConnected) return;
    this.rconConnecting = true;
    try {
      this.rcon = await Rcon.connect(this.rconConfig);
      this.rconConnected = true;
      console.log(`[${this.id}] RCON connected`);
      this.rcon.on("end", () => {
        console.log(`[${this.id}] RCON ended; reconnecting in 30s`);
        this.rconConnected = false;
        this.rconConnecting = false;
        setTimeout(() => this._connectRconRetry().catch(() => {}), 30000);
      });
      this.rcon.on("error", (err) => {
        console.error(`[${this.id}] RCON error:`, err.message);
        this.rconConnected = false;
        this.rconConnecting = false;
      });
    } catch (err) {
      this.rconConnecting = false;
      this.rconConnected = false;
      throw err;
    }
  }

  async _connectRconRetry(retries = 15, delay = 10000) {
    for (let i = 0; i < retries; i++) {
      try {
        await this._connectRcon();
        if (this.rconConnected) return;
      } catch {
        // swallow and retry
      }
      await new Promise((res) => setTimeout(res, delay));
    }
    console.error(`[${this.id}] Could not connect to RCON after ${retries} retries`);
  }

  _scheduleConnect(delayMs) {
    setTimeout(() => this._connectRconRetry().catch(() => {}), delayMs);
  }

  isRconConnected() {
    return this.rconConnected;
  }

  async rconSend(cmd) {
    if (!this.rcon || !this.rconConnected) {
      throw new Error("Not connected to RCON");
    }
    return this.rcon.send(cmd);
  }

  // ---- Lifecycle ----------------------------------------------------------

  async start() {
    await this.dockerAction("start");
    this._scheduleConnect(40000);
    return "starting";
  }

  async stop() {
    try {
      await this.rconSend("stop");
    } catch {
      await this.dockerAction("stop");
    }
    this.rconConnected = false;
    return "stopping";
  }

  async status() {
    let running = false;
    let players = [];
    try {
      const response = await this.rconSend("list");
      const match = response.match(/There are (\d+) of a max of \d+ players online:(.*)/);
      if (match) {
        players = match[2]
          .split(",")
          .map((p) => p.trim())
          .filter(Boolean);
      }
      running = true;
    } catch {
      running = false;
    }
    let currentWorld = null;
    if (fs.existsSync(this.currentWorldFile)) {
      currentWorld = fs.readFileSync(this.currentWorldFile, "utf8").trim() || null;
    }
    return {
      running,
      players,
      details: {
        rconConnected: this.rconConnected,
        currentWorld,
      },
    };
  }

  // ---- Logs ---------------------------------------------------------------

  async logs(lines = 100) {
    if (fs.existsSync(this.logFile)) {
      const content = fs.readFileSync(this.logFile, "utf8");
      return content.split("\n").filter(Boolean).slice(-lines);
    }
    // Fall back to docker logs if log file is not bind-mounted
    return super.logs(lines);
  }

  // ---- Whitelist / OP -----------------------------------------------------

  async whitelistList() {
    return this.rconSend("whitelist list");
  }
  async whitelistAdd(player) {
    return this.rconSend(`whitelist add ${player}`);
  }
  async whitelistRemove(player) {
    return this.rconSend(`whitelist remove ${player}`);
  }
  async opAdd(player) {
    return this.rconSend(`op ${player}`);
  }
  async opRemove(player) {
    return this.rconSend(`deop ${player}`);
  }

  // ---- Backups ------------------------------------------------------------

  async backup() {
    if (!fs.existsSync(this.activeWorldDir)) {
      throw new Error("No active world found");
    }
    let currentWorldName = "world";
    if (fs.existsSync(this.currentWorldFile)) {
      currentWorldName =
        fs.readFileSync(this.currentWorldFile, "utf8").trim() || "world";
    }
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const backupName = `${currentWorldName}-${timestamp}`;
    const backupPath = path.join(this.backupsDir, backupName);

    if (this.rconConnected) {
      try {
        await this.rconSend("say Server backup in progress...");
      } catch {
        // ignore
      }
    }
    fs.copySync(this.activeWorldDir, backupPath);

    // Keep only the 5 most recent backups for this instance
    const all = fs
      .readdirSync(this.backupsDir)
      .filter((f) => fs.statSync(path.join(this.backupsDir, f)).isDirectory())
      .sort(
        (a, b) =>
          fs.statSync(path.join(this.backupsDir, b)).mtime -
          fs.statSync(path.join(this.backupsDir, a)).mtime,
      );
    while (all.length > 5) {
      const oldest = all.pop();
      fs.rmSync(path.join(this.backupsDir, oldest), { recursive: true, force: true });
    }
    return { name: backupName, path: backupPath };
  }

  listBackups() {
    if (!fs.existsSync(this.backupsDir)) return [];
    return fs
      .readdirSync(this.backupsDir)
      .filter((f) => fs.statSync(path.join(this.backupsDir, f)).isDirectory())
      .sort(
        (a, b) =>
          fs.statSync(path.join(this.backupsDir, b)).mtime -
          fs.statSync(path.join(this.backupsDir, a)).mtime,
      );
  }

  async restoreBackup(name) {
    const backupPath = path.join(this.backupsDir, name);
    if (!fs.existsSync(backupPath)) {
      throw new Error("Backup folder not found");
    }
    if (this.rconConnected) {
      try {
        await this.rconSend("say Restoring backup... server restarting!");
        await this.rconSend("stop");
      } catch {
        // ignore
      }
    }
    this.rconConnected = false;
    setTimeout(async () => {
      try {
        fs.rmSync(this.activeWorldDir, { recursive: true, force: true });
        fs.copySync(backupPath, this.activeWorldDir);
        fs.rmSync(path.join(this.activeWorldDir, "session.lock"), { force: true });
        await this._fixOwnership(this.activeWorldDir);
        const worldName = name.replace(/-\d{4}-\d{2}-\d{2}T.*$/, "");
        if (worldName) fs.writeFileSync(this.currentWorldFile, worldName);
        await this.dockerAction("start");
      } catch (err) {
        console.error(`[${this.id}] Restore error:`, err.message);
      }
    }, 15000);
    setTimeout(() => this._connectRconRetry().catch(() => {}), 60000);
    return { restoring: name };
  }

  // ---- Worlds -------------------------------------------------------------

  listWorlds() {
    let worlds = [];
    if (fs.existsSync(this.worldsDir)) {
      worlds = fs
        .readdirSync(this.worldsDir)
        .filter((f) => fs.statSync(path.join(this.worldsDir, f)).isDirectory());
    }
    let currentWorld = null;
    if (fs.existsSync(this.currentWorldFile)) {
      currentWorld = fs.readFileSync(this.currentWorldFile, "utf8").trim() || null;
    }
    return { worlds, currentWorld };
  }

  saveCurrentWorld() {
    if (!fs.existsSync(this.activeWorldDir)) {
      throw new Error("No active world folder found");
    }
    if (!fs.existsSync(this.currentWorldFile)) {
      throw new Error("No current-world.txt found - unknown world name");
    }
    const currentWorldName = fs.readFileSync(this.currentWorldFile, "utf8").trim();
    if (!currentWorldName) throw new Error("current-world.txt is empty");
    const dest = path.join(this.worldsDir, currentWorldName);
    fs.copySync(this.activeWorldDir, dest);
    return currentWorldName;
  }

  async changeWorld(name) {
    const newWorldPath = path.join(this.worldsDir, name);
    if (!fs.existsSync(newWorldPath)) {
      throw new Error("World not found");
    }
    let oldWorldName = null;
    if (fs.existsSync(this.currentWorldFile)) {
      oldWorldName = fs.readFileSync(this.currentWorldFile, "utf8").trim();
    }
    if (this.rconConnected) {
      try {
        await this.rconSend("say Switching world... server restarting!");
        await this.rconSend("stop");
      } catch {
        // ignore
      }
    }
    this.rconConnected = false;
    setTimeout(async () => {
      try {
        if (oldWorldName && fs.existsSync(this.activeWorldDir)) {
          fs.copySync(this.activeWorldDir, path.join(this.worldsDir, oldWorldName));
        }
        fs.rmSync(this.activeWorldDir, { recursive: true, force: true });
        fs.copySync(newWorldPath, this.activeWorldDir);
        fs.rmSync(path.join(this.activeWorldDir, "session.lock"), { force: true });
        await this._fixOwnership(this.activeWorldDir);
        fs.writeFileSync(this.currentWorldFile, name);
        await this.dockerAction("start");
      } catch (err) {
        console.error(`[${this.id}] World switch error:`, err.message);
      }
    }, 15000);
    setTimeout(() => this._connectRconRetry().catch(() => {}), 60000);
    return { switching: name };
  }

  async newWorld(name) {
    let oldWorldName = null;
    if (fs.existsSync(this.currentWorldFile)) {
      oldWorldName = fs.readFileSync(this.currentWorldFile, "utf8").trim();
    }
    if (this.rconConnected) {
      try {
        await this.rconSend("say Generating new world... server restarting!");
        await this.rconSend("stop");
      } catch {
        // ignore
      }
    }
    this.rconConnected = false;
    setTimeout(async () => {
      try {
        if (oldWorldName && fs.existsSync(this.activeWorldDir)) {
          fs.copySync(this.activeWorldDir, path.join(this.worldsDir, oldWorldName));
        }
        fs.rmSync(this.activeWorldDir, { recursive: true, force: true });
        fs.writeFileSync(this.currentWorldFile, name);
        await this.dockerAction("start");
      } catch (err) {
        console.error(`[${this.id}] New world error:`, err.message);
      }
    }, 15000);
    setTimeout(() => {
      if (fs.existsSync(this.activeWorldDir)) {
        fs.copySync(this.activeWorldDir, path.join(this.worldsDir, name));
      }
    }, 60000);
    setTimeout(() => this._connectRconRetry().catch(() => {}), 65000);
    return { creating: name };
  }

  _fixOwnership(targetPath) {
    return new Promise((resolve) => {
      exec(`chown -R 1000:1000 "${targetPath}"`, (err) => {
        if (err) console.error(`[${this.id}] chown failed:`, err.message);
        resolve();
      });
    });
  }
}

module.exports = MinecraftAdapter;
