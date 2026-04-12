/**
 * Minecraft adapter — RCON control, whitelist/op management, world
 * switching, backups. Per-instance so multiple MC servers can run in
 * the same stack.
 *
 * RCON connection lifecycle is managed by `RconConnection` (exponential
 * backoff reconnect) rather than the manual retry loop we had before.
 *
 * RCON commands sent from the knock/admin routes go through a narrow
 * whitelist of allowed commands (see `ALLOWED_RCON_COMMANDS`). Arbitrary
 * user-supplied strings are only permitted from routes that are gated
 * behind admin auth.
 *
 * When `dataDir` is omitted from services.json, the adapter still loads
 * with full RCON support (start/stop, whitelist, op, players) but
 * filesystem features (backup, world-switching, logs) are disabled.
 */

import * as fs from "node:fs";
import * as fsExtra from "fs-extra";
import * as path from "node:path";
import { runCmd } from "../lib/exec";
import { logger } from "../logger";
import { RconConnection } from "../lib/rcon-pool";
import { BaseAdapter } from "./base";
import type { BackupInfo, ServiceStatus, WorldsInfo } from "./types";
import type { ServiceConfig } from "../schemas";

const MAX_BACKUPS = 5;

/**
 * Common BlueMap data paths (relative to the MC data dir).
 * We check them in order and use the first one that exists.
 */
const BLUEMAP_CANDIDATES = [
  "bluemap/web/maps",
  "plugins/BlueMap/web/maps",
  "plugins/bluemap/web/maps",
];

export class MinecraftAdapter extends BaseAdapter {
  private readonly rcon: RconConnection;
  private readonly hasDataDir: boolean;
  private readonly dataDir: string;
  private readonly logFile: string;
  private readonly backupsDir: string;
  private readonly worldsDir: string;
  private readonly activeWorldDir: string;
  private readonly currentWorldFile: string;

  constructor(config: ServiceConfig) {
    super(config);
    this.capabilities.add("rcon");
    this.capabilities.add("whitelist");
    this.capabilities.add("op");
    this.capabilities.add("players");

    const rconHost = config.rcon?.host ?? config.container;
    const rconPort = config.rcon?.port ?? 25575;
    const password =
      config.rcon?.password ??
      (config.rcon?.passwordEnv ? process.env[config.rcon.passwordEnv] : undefined) ??
      process.env["RCON_PASSWORD"] ??
      "changeme";

    this.rcon = new RconConnection(config.id, {
      host: rconHost,
      port: rconPort,
      password,
    });

    this.hasDataDir = !!config.dataDir;
    this.dataDir = config.dataDir ?? "";
    this.logFile = config.logFile
      ? path.isAbsolute(config.logFile)
        ? config.logFile
        : path.join(this.dataDir, config.logFile)
      : path.join(this.dataDir, "logs", "latest.log");
    this.backupsDir = config.backupsDir ?? path.join(this.dataDir, "backups");
    this.worldsDir = config.worldsDir ?? path.join(this.dataDir, "worlds");
    this.activeWorldDir = config.activeWorldDir ?? path.join(this.dataDir, "world");
    this.currentWorldFile =
      config.currentWorldFile ?? path.join(this.dataDir, "current-world.txt");

    if (this.hasDataDir) {
      fsExtra.ensureDirSync(this.backupsDir);
      fsExtra.ensureDirSync(this.worldsDir);
      this.capabilities.add("logs");
      this.capabilities.add("backup");
      this.capabilities.add("worlds");
    } else {
      logger().warn(
        { id: config.id },
        "no dataDir configured — backup, worlds, and log features disabled (RCON still works)",
      );
    }

    this.rcon.start();
  }

  isRconConnected(): boolean {
    return this.rcon.isConnected();
  }

  async rconSend(command: string): Promise<string> {
    return this.rcon.send(command);
  }

  override async start(): Promise<string> {
    await this.dockerAction("start");
    this.rcon.start();
    return "starting";
  }

  override async stop(): Promise<string> {
    try {
      if (this.rcon.isConnected()) await this.rcon.send("stop");
    } catch {
      // fall back to docker stop
    }
    try {
      await this.dockerAction("stop");
    } catch {
      // ignore
    }
    return "stopping";
  }

  override async status(): Promise<ServiceStatus> {
    let running = false;
    let players: string[] = [];
    try {
      const response = await this.rcon.send("list");
      const match = response.match(/There are (\d+) of a max of \d+ players online:(.*)/u);
      if (match) {
        players = match[2]!
          .split(",")
          .map((p) => p.trim())
          .filter(Boolean);
      }
      running = true;
    } catch {
      running = false;
    }
    let currentWorld: string | null = null;
    if (this.hasDataDir && fs.existsSync(this.currentWorldFile)) {
      currentWorld = fs.readFileSync(this.currentWorldFile, "utf8").trim() || null;
    }
    return {
      running,
      players,
      details: {
        rconConnected: this.rcon.isConnected(),
        currentWorld,
      },
    };
  }

  override async logs(lines = 100): Promise<string[]> {
    if (this.hasDataDir && fs.existsSync(this.logFile)) {
      const content = fs.readFileSync(this.logFile, "utf8");
      return content.split("\n").filter(Boolean).slice(-lines);
    }
    return super.logs(lines);
  }

  async whitelistList(): Promise<string> {
    return this.rcon.send("whitelist list");
  }
  async whitelistAdd(player: string): Promise<string> {
    return this.rcon.send(`whitelist add ${player}`);
  }
  async whitelistRemove(player: string): Promise<string> {
    return this.rcon.send(`whitelist remove ${player}`);
  }
  async opAdd(player: string): Promise<string> {
    return this.rcon.send(`op ${player}`);
  }
  async opRemove(player: string): Promise<string> {
    return this.rcon.send(`deop ${player}`);
  }

  private requireDataDir(): void {
    if (!this.hasDataDir) {
      throw new Error("dataDir not configured — mount the MC server data and set dataDir in services.json");
    }
  }

  async backup(): Promise<BackupInfo> {
    this.requireDataDir();
    if (!fs.existsSync(this.activeWorldDir)) {
      throw new Error("No active world found");
    }
    let currentWorldName = "world";
    if (fs.existsSync(this.currentWorldFile)) {
      currentWorldName =
        fs.readFileSync(this.currentWorldFile, "utf8").trim() || "world";
    }
    const timestamp = new Date().toISOString().replace(/[:.]/gu, "-");
    const backupName = `${currentWorldName}-${timestamp}`;
    const backupPath = path.join(this.backupsDir, backupName);

    // If RCON is connected the server is live — disable autosave and
    // flush outstanding chunks to disk before we copy, so we don't
    // catch a region file mid-write. Re-enable autosave in a finally
    // block so a failed copy doesn't leave the server stuck with
    // saving disabled forever (which would eventually lose data).
    //
    // `save-all flush` blocks on Paper/Spigot until every chunk is
    // written, but we still wait a short settle before the copy to
    // cover FS buffering (and NFS-mounted data dirs).
    const serverIsLive = this.rcon.isConnected();
    let autosaveDisabled = false;
    try {
      if (serverIsLive) {
        try {
          await this.rcon.send("say Server backup in progress...");
        } catch {
          // cosmetic broadcast; ignore failure
        }
        try {
          await this.rcon.send("save-off");
          autosaveDisabled = true;
          await this.rcon.send("save-all flush");
          await new Promise<void>((resolve) => setTimeout(resolve, 500));
        } catch (err) {
          logger().warn(
            { err: (err as Error).message, id: this.id },
            "backup: rcon flush failed, copying anyway",
          );
        }
      }
      fsExtra.copySync(this.activeWorldDir, backupPath);
      this.saveBluemapData(backupPath);
    } finally {
      if (autosaveDisabled) {
        try {
          await this.rcon.send("save-on");
        } catch (err) {
          // Failing to re-enable autosave is genuinely bad — the
          // server will stop persisting player actions. Log loudly.
          logger().error(
            { err: (err as Error).message, id: this.id },
            "backup: FAILED to re-enable autosave via save-on",
          );
        }
      }
    }
    this.pruneOldBackups();
    return { name: backupName, path: backupPath };
  }

  listBackups(): string[] {
    if (!this.hasDataDir || !fs.existsSync(this.backupsDir)) return [];
    return fs
      .readdirSync(this.backupsDir)
      .filter((f) => fs.statSync(path.join(this.backupsDir, f)).isDirectory())
      .sort((a, b) => {
        const bStat = fs.statSync(path.join(this.backupsDir, b));
        const aStat = fs.statSync(path.join(this.backupsDir, a));
        return bStat.mtime.getTime() - aStat.mtime.getTime();
      });
  }

  private pruneOldBackups(): void {
    const all = this.listBackups();
    while (all.length > MAX_BACKUPS) {
      const oldest = all.pop();
      if (!oldest) break;
      try {
        fs.rmSync(path.join(this.backupsDir, oldest), { recursive: true, force: true });
      } catch (err) {
        logger().warn({ err: (err as Error).message, backup: oldest }, "prune backup failed");
      }
    }
  }

  async restoreBackup(name: string): Promise<{ restoring: string }> {
    this.requireDataDir();
    const backupPath = path.join(this.backupsDir, name);
    if (!fs.existsSync(backupPath)) {
      throw new Error("Backup folder not found");
    }
    try {
      if (this.rcon.isConnected()) {
        await this.rcon.send("say Restoring backup... server restarting!");
        await this.rcon.send("stop");
      }
    } catch {
      // ignore
    }
    // Defer the actual restore so the MC process has time to shut down.
    setTimeout(() => {
      this.applyRestore(backupPath, name).catch((err: Error) => {
        logger().error({ err: err.message, id: this.id }, "restore failed");
      });
    }, 15_000);
    return { restoring: name };
  }

  private async applyRestore(backupPath: string, name: string): Promise<void> {
    fs.rmSync(this.activeWorldDir, { recursive: true, force: true });
    fsExtra.copySync(backupPath, this.activeWorldDir);
    try {
      fs.rmSync(path.join(this.activeWorldDir, "session.lock"), { force: true });
    } catch {
      // ignore
    }
    await this.fixOwnership(this.activeWorldDir);
    // Restore BlueMap tiles if the backup has them
    this.restoreBluemapData(backupPath);
    const worldName = name.replace(/-\d{4}-\d{2}-\d{2}T.*$/u, "");
    if (worldName) fs.writeFileSync(this.currentWorldFile, worldName);
    await this.dockerAction("start");
  }

  listWorlds(): WorldsInfo {
    let worlds: string[] = [];
    if (this.hasDataDir && fs.existsSync(this.worldsDir)) {
      worlds = fs
        .readdirSync(this.worldsDir)
        .filter((f) => fs.statSync(path.join(this.worldsDir, f)).isDirectory());
    }
    let currentWorld: string | null = null;
    if (this.hasDataDir && fs.existsSync(this.currentWorldFile)) {
      currentWorld = fs.readFileSync(this.currentWorldFile, "utf8").trim() || null;
    }
    return { worlds, currentWorld };
  }

  saveCurrentWorld(): string {
    this.requireDataDir();
    if (!fs.existsSync(this.activeWorldDir)) {
      throw new Error("No active world folder found");
    }
    if (!fs.existsSync(this.currentWorldFile)) {
      throw new Error("No current-world.txt found - unknown world name");
    }
    const currentWorldName = fs.readFileSync(this.currentWorldFile, "utf8").trim();
    if (!currentWorldName) throw new Error("current-world.txt is empty");
    const dest = path.join(this.worldsDir, currentWorldName);
    fsExtra.copySync(this.activeWorldDir, dest);
    this.saveBluemapData(dest);
    return currentWorldName;
  }

  async changeWorld(name: string): Promise<{ switching: string }> {
    this.requireDataDir();
    const newWorldPath = path.join(this.worldsDir, name);
    if (!fs.existsSync(newWorldPath)) {
      throw new Error("World not found");
    }
    const oldWorldName = fs.existsSync(this.currentWorldFile)
      ? fs.readFileSync(this.currentWorldFile, "utf8").trim()
      : null;
    try {
      if (this.rcon.isConnected()) {
        await this.rcon.send("say Switching world... server restarting!");
        await this.rcon.send("stop");
      }
    } catch {
      // ignore
    }
    setTimeout(() => {
      this.applyWorldSwitch(newWorldPath, oldWorldName, name).catch((err: Error) => {
        logger().error({ err: err.message, id: this.id }, "world switch failed");
      });
    }, 15_000);
    return { switching: name };
  }

  private async applyWorldSwitch(
    newWorldPath: string,
    oldWorldName: string | null,
    name: string,
  ): Promise<void> {
    // Save old world + its BlueMap tiles
    if (oldWorldName && fs.existsSync(this.activeWorldDir)) {
      const oldSave = path.join(this.worldsDir, oldWorldName);
      fsExtra.copySync(this.activeWorldDir, oldSave);
      this.saveBluemapData(oldSave);
    }
    fs.rmSync(this.activeWorldDir, { recursive: true, force: true });
    fsExtra.copySync(newWorldPath, this.activeWorldDir);
    try {
      fs.rmSync(path.join(this.activeWorldDir, "session.lock"), { force: true });
    } catch {
      // ignore
    }
    await this.fixOwnership(this.activeWorldDir);
    // Restore BlueMap tiles for the new world (if previously saved)
    this.restoreBluemapData(newWorldPath);
    fs.writeFileSync(this.currentWorldFile, name);
    await this.dockerAction("start");
  }

  async newWorld(name: string): Promise<{ creating: string }> {
    this.requireDataDir();
    const oldWorldName = fs.existsSync(this.currentWorldFile)
      ? fs.readFileSync(this.currentWorldFile, "utf8").trim()
      : null;
    try {
      if (this.rcon.isConnected()) {
        await this.rcon.send("say Generating new world... server restarting!");
        await this.rcon.send("stop");
      }
    } catch {
      // ignore
    }
    setTimeout(() => {
      this.applyNewWorld(oldWorldName, name).catch((err: Error) => {
        logger().error({ err: err.message, id: this.id }, "new world failed");
      });
    }, 15_000);
    return { creating: name };
  }

  private async applyNewWorld(oldWorldName: string | null, name: string): Promise<void> {
    // Save old world + its BlueMap tiles before wiping
    if (oldWorldName && fs.existsSync(this.activeWorldDir)) {
      const oldSave = path.join(this.worldsDir, oldWorldName);
      fsExtra.copySync(this.activeWorldDir, oldSave);
      this.saveBluemapData(oldSave);
    }
    fs.rmSync(this.activeWorldDir, { recursive: true, force: true });
    fs.writeFileSync(this.currentWorldFile, name);
    await this.dockerAction("start");
  }

  // ── BlueMap tile management ──────────────────────────────────────────

  /**
   * Find the active BlueMap maps directory, or null if BlueMap isn't
   * installed. Caches nothing — the dir might appear after a plugin
   * install or server restart.
   */
  private findBluemapMapsDir(): string | null {
    if (!this.hasDataDir) return null;
    for (const candidate of BLUEMAP_CANDIDATES) {
      const p = path.join(this.dataDir, candidate);
      if (fs.existsSync(p)) return p;
    }
    return null;
  }

  /**
   * Copy BlueMap rendered tiles into a world save dir so they travel
   * with the world. Stored as `.bluemap-maps/` inside the world dir.
   */
  private saveBluemapData(worldSaveDir: string): void {
    const mapsDir = this.findBluemapMapsDir();
    if (!mapsDir) return;
    const dest = path.join(worldSaveDir, ".bluemap-maps");
    try {
      if (fs.existsSync(dest)) {
        fs.rmSync(dest, { recursive: true, force: true });
      }
      fsExtra.copySync(mapsDir, dest);
      logger().info({ id: this.id, dest }, "saved BlueMap tiles with world");
    } catch (err) {
      logger().warn(
        { err: (err as Error).message, id: this.id },
        "failed to save BlueMap tiles — map will re-render after switch",
      );
    }
  }

  /**
   * Restore BlueMap tiles from a world save dir, if present.
   * Replaces the current BlueMap maps directory entirely.
   */
  private restoreBluemapData(worldSaveDir: string): void {
    const mapsDir = this.findBluemapMapsDir();
    if (!mapsDir) return;
    const src = path.join(worldSaveDir, ".bluemap-maps");
    if (!fs.existsSync(src)) {
      // No saved tiles — BlueMap will re-render from scratch.
      logger().info({ id: this.id }, "no saved BlueMap tiles for this world — will re-render");
      return;
    }
    try {
      fs.rmSync(mapsDir, { recursive: true, force: true });
      fsExtra.copySync(src, mapsDir);
      logger().info({ id: this.id }, "restored BlueMap tiles from world save");
    } catch (err) {
      logger().warn(
        { err: (err as Error).message, id: this.id },
        "failed to restore BlueMap tiles — map will re-render",
      );
    }
  }

  private async fixOwnership(targetPath: string): Promise<void> {
    try {
      await runCmd("chown", ["-R", "1000:1000", targetPath], { timeoutMs: 10_000 });
    } catch (err) {
      logger().warn({ err: (err as Error).message, targetPath }, "chown failed");
    }
  }

  async dispose(): Promise<void> {
    await this.rcon.stop();
  }
}
