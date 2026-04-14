/**
 * TShock (Terraria) adapter — extends generic lifecycle with player and
 * world data from the TShock REST API.
 *
 * TShock exposes a REST API on port 7878 by default. We call:
 *   GET /v2/server/status?players=true[&token=<token>]
 *
 * Returns server name, port, playercount, maxplayers, world, uptime,
 * versions, and a structured players array (nickname, username,
 * group, active, state, team).
 *
 * Auth modes (set in TShock's config.json under Settings):
 *   EnableTokenEndpointAuthentication = true  → all endpoints require
 *     a token. Use an Application REST Token (survives restart) and
 *     set it as `tshockApiToken` in services.json.
 *   EnableTokenEndpointAuthentication = false → /v2/server/status,
 *     /v3/server/motd and /v3/server/rules are OPEN (no token needed).
 *     Fine for localhost-only setups. `tshockApiToken` can be omitted.
 */

import { logger } from "../logger";
import { GenericAdapter } from "./generic";
import type { ServiceConfig } from "../schemas";
import type { ServiceStatus } from "./types";

const API_TIMEOUT_MS = 5_000;

interface TShockPlayer {
  nickname: string;
  username: string;
  ip?: string;
  group?: string;
  active: boolean;
  state?: number;
  team?: number;
}

interface TShockServerStatusResponse {
  status: string;
  name?: string;
  serverversion?: string;
  tshockversion?: string;
  port?: number;
  playercount?: number;
  maxplayers?: number;
  world?: string;
  uptime?: string;
  serverpassword?: boolean;
  players?: TShockPlayer[];
}

export class TShockAdapter extends GenericAdapter {
  private readonly apiUrl: string;
  private readonly apiToken: string;

  constructor(config: ServiceConfig) {
    super(config);
    this.apiUrl =
      config.tshockApiUrl ?? `http://${config.container}:7878`;
    this.apiToken = config.tshockApiToken ?? "";
    // `/v2/server/status` is available either way:
    //  - with a valid token when EnableTokenEndpointAuthentication=true
    //  - without a token when it's false
    // A failed fetch at runtime just returns `null` and degrades gracefully.
    this.capabilities.add("players");
  }

  private async fetchServerStatus(): Promise<TShockServerStatusResponse | null> {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), API_TIMEOUT_MS);
      try {
        const params = new URLSearchParams({ players: "true" });
        if (this.apiToken) params.set("token", this.apiToken);
        const url = `${this.apiUrl}/v2/server/status?${params.toString()}`;
        const res = await fetch(url, { signal: controller.signal });
        if (!res.ok) return null;
        const data = (await res.json()) as TShockServerStatusResponse;
        if (data.status !== "200") return null;
        return data;
      } finally {
        clearTimeout(timer);
      }
    } catch (err) {
      logger().debug(
        { err: (err as Error).message, service: this.id },
        "tshock API fetch failed",
      );
      return null;
    }
  }

  override async status(): Promise<ServiceStatus> {
    const base = await super.status();
    if (!base.running) return base;

    const data = await this.fetchServerStatus();
    if (!data) return base;

    const players = (data.players ?? [])
      .filter((p) => p.active)
      .map((p) => p.nickname || p.username)
      .filter(Boolean);

    return {
      running: true,
      players,
      details: {
        ...base.details,
        world: data.world ?? null,
        maxPlayers: data.maxplayers ?? null,
        serverName: data.name ?? null,
        uptime: data.uptime ?? null,
        serverVersion: data.serverversion ?? null,
        tshockVersion: data.tshockversion ?? null,
      },
    };
  }
}
