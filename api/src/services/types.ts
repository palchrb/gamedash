/**
 * Service adapter interface.
 *
 * Concrete adapters (minecraft, generic) implement a subset of these
 * methods and advertise their supported operations via `capabilities`.
 * Routes check `hasCapability()` before calling optional methods so we
 * return a clear 400 for unsupported operations instead of crashing.
 */

import type { PortSpec } from "../schemas";

export type Capability =
  | "lifecycle"
  | "logs"
  | "rcon"
  | "whitelist"
  | "op"
  | "backup"
  | "worlds"
  | "players";

export interface ServiceStatus {
  running: boolean;
  players: string[];
  details: Record<string, unknown>;
}

export interface BackupInfo {
  name: string;
  path: string;
}

export interface WorldsInfo {
  worlds: string[];
  currentWorld: string | null;
}

export interface ServiceDescriptor {
  id: string;
  name: string;
  type: string;
  container: string;
  ports: PortSpec[];
  capabilities: Capability[];
}

export interface ServiceAdapter {
  readonly id: string;
  readonly name: string;
  readonly type: string;
  readonly container: string;
  readonly ports: PortSpec[];
  readonly capabilities: Set<Capability>;

  hasCapability(cap: Capability): boolean;
  describe(): ServiceDescriptor;

  status(): Promise<ServiceStatus>;
  start(): Promise<string>;
  stop(): Promise<string>;
  restart(): Promise<string>;
  logs(lines?: number): Promise<string[]>;

  // Optional — only available if the matching capability is advertised.
  rconSend?(command: string): Promise<string>;
  isRconConnected?(): boolean;

  whitelistList?(): Promise<string>;
  whitelistAdd?(player: string): Promise<string>;
  whitelistRemove?(player: string): Promise<string>;

  opAdd?(player: string): Promise<string>;
  opRemove?(player: string): Promise<string>;

  backup?(): Promise<BackupInfo>;
  listBackups?(): string[];
  restoreBackup?(name: string): Promise<{ restoring: string }>;

  listWorlds?(): WorldsInfo;
  saveCurrentWorld?(): string;
  changeWorld?(name: string): Promise<{ switching: string }>;
  newWorld?(name: string): Promise<{ creating: string }>;

  dispose?(): Promise<void>;
}
