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

export class MinecraftAdapter extends BaseAdapter {
  private readonly rcon: RconConnection;
  private readonly dataDir: string;
  private readonly logFile: string;
  private readonly backupsDir: string;
  private readonly worldsDir: string;
  private readonly activeWorldDir: string;
  private readonly currentWorldFile: string;

  constructor(config: ServiceConfig) {
    super(config);
    this.capabilities.add("logs");
    this.capabilities.add("rcon");
    this.capabilities.add("whitelist");
    this.capabilities.add("op");
    this.capabilities.add("backup");
    this.capabilities.add("worlds");
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

    this.dataDir = config.dataDir ?? "/data";
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

    fsExtra.ensureDirSync(this.backupsDir);
    fsExtra.ensureDirSync(this.worldsDir);

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
    if (fs.existsSync(this.currentWorldFile)) {
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
    if (fs.existsSync(this.logFile)) {
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

  async backup(): Promise<BackupInfo> {
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

    try {
      if (this.rcon.isConnected()) await this.rcon.send("say Server backup in progress...");
    } catch {
      // ignore
    }
    fsExtra.copySync(this.activeWorldDir, backupPath);
    this.pruneOldBackups();
    return { name: backupName, path: backupPath };
  }

  listBackups(): string[] {
    if (!fs.existsSync(this.backupsDir)) return [];
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
    const worldName = name.replace(/-\d{4}-\d{2}-\d{2}T.*$/u, "");
    if (worldName) fs.writeFileSync(this.currentWorldFile, worldName);
    await this.dockerAction("start");
  }

  listWorlds(): WorldsInfo {
    let worlds: string[] = [];
    if (fs.existsSync(this.worldsDir)) {
      worlds = fs
        .readdirSync(this.worldsDir)
        .filter((f) => fs.statSync(path.join(this.worldsDir, f)).isDirectory());
    }
    let currentWorld: string | null = null;
    if (fs.existsSync(this.currentWorldFile)) {
      currentWorld = fs.readFileSync(this.currentWorldFile, "utf8").trim() || null;
    }
    return { worlds, currentWorld };
  }

  saveCurrentWorld(): string {
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
    return currentWorldName;
  }

  async changeWorld(name: string): Promise<{ switching: string }> {
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
    if (oldWorldName && fs.existsSync(this.activeWorldDir)) {
      fsExtra.copySync(this.activeWorldDir, path.join(this.worldsDir, oldWorldName));
    }
    fs.rmSync(this.activeWorldDir, { recursive: true, force: true });
    fsExtra.copySync(newWorldPath, this.activeWorldDir);
    try {
      fs.rmSync(path.join(this.activeWorldDir, "session.lock"), { force: true });
    } catch {
      // ignore
    }
    await this.fixOwnership(this.activeWorldDir);
    fs.writeFileSync(this.currentWorldFile, name);
    await this.dockerAction("start");
  }

  async newWorld(name: string): Promise<{ creating: string }> {
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
    if (oldWorldName && fs.existsSync(this.activeWorldDir)) {
      fsExtra.copySync(this.activeWorldDir, path.join(this.worldsDir, oldWorldName));
    }
    fs.rmSync(this.activeWorldDir, { recursive: true, force: true });
    fs.writeFileSync(this.currentWorldFile, name);
    await this.dockerAction("start");
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
