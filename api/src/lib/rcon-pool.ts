/**
 * RCON connection manager with exponential backoff reconnect.
 *
 * The old code had a hand-rolled "scheduleConnect" with hardcoded 30/40/60s
 * timeouts and manual retry state. This class does the same thing with:
 *   - single source of truth for connection state
 *   - bounded exponential backoff (1s → 60s)
 *   - per-command timeout
 *   - survives container restarts without leaking listeners
 *
 * Commands sent while disconnected throw immediately — the caller should
 * surface a friendly "RCON not connected" error rather than blocking.
 */

import { Rcon } from "rcon-client";
import { logger } from "../logger";

export interface RconOptions {
  host: string;
  port: number;
  password: string;
}

interface Connection {
  client: Rcon;
  connectedAt: number;
}

const INITIAL_BACKOFF_MS = 1_000;
const MAX_BACKOFF_MS = 60_000;
const COMMAND_TIMEOUT_MS = 10_000;
const CONNECT_TIMEOUT_MS = 5_000;

export class RconConnection {
  private readonly id: string;
  private readonly options: RconOptions;
  private connection: Connection | null = null;
  private connecting = false;
  private backoffMs = INITIAL_BACKOFF_MS;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private stopped = false;

  constructor(id: string, options: RconOptions) {
    this.id = id;
    this.options = options;
  }

  /** Begin connecting in the background. Safe to call repeatedly. */
  start(): void {
    this.stopped = false;
    this.scheduleConnect(0);
  }

  /** Stop reconnecting and close the current connection. */
  async stop(): Promise<void> {
    this.stopped = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    const current = this.connection;
    this.connection = null;
    if (current) {
      try {
        await current.client.end();
      } catch {
        // ignore
      }
    }
  }

  isConnected(): boolean {
    return this.connection !== null;
  }

  /** Wait up to `deadlineMs` for a connection to be established. */
  async waitForConnection(deadlineMs: number): Promise<boolean> {
    const start = Date.now();
    while (!this.isConnected() && Date.now() - start < deadlineMs) {
      await new Promise((r) => setTimeout(r, 250));
    }
    return this.isConnected();
  }

  /** Send a command. Throws if not connected or the command times out. */
  async send(command: string): Promise<string> {
    const current = this.connection;
    if (!current) throw new Error(`RCON [${this.id}] not connected`);
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error(`RCON [${this.id}] command timeout`)), COMMAND_TIMEOUT_MS);
    });
    return Promise.race([current.client.send(command), timeoutPromise]);
  }

  private scheduleConnect(delayMs: number): void {
    if (this.stopped) return;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.reconnectTimer = setTimeout(() => {
      this.connect().catch(() => {
        // swallow; connect() schedules its own retry via scheduleConnect
      });
    }, delayMs);
  }

  private async connect(): Promise<void> {
    if (this.stopped || this.connecting || this.connection) return;
    this.connecting = true;
    const log = logger().child({ mod: "rcon", id: this.id });
    try {
      const client = await Promise.race([
        Rcon.connect(this.options),
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error("RCON connect timeout")), CONNECT_TIMEOUT_MS),
        ),
      ]);
      this.connection = { client, connectedAt: Date.now() };
      this.backoffMs = INITIAL_BACKOFF_MS;
      log.info("connected");

      client.on("end", () => {
        log.info("connection ended");
        this.connection = null;
        this.scheduleConnect(this.nextBackoff());
      });
      client.on("error", (err: Error) => {
        log.warn({ err: err.message }, "rcon error");
        this.connection = null;
        this.scheduleConnect(this.nextBackoff());
      });
    } catch (err) {
      log.debug({ err: (err as Error).message }, "connect failed, retrying");
      this.connection = null;
      this.scheduleConnect(this.nextBackoff());
    } finally {
      this.connecting = false;
    }
  }

  private nextBackoff(): number {
    const current = this.backoffMs;
    this.backoffMs = Math.min(current * 2, MAX_BACKOFF_MS);
    return current;
  }
}
