/**
 * Impostor (Among Us) adapter — extends generic lifecycle with live
 * game and player state from the Impostor.Plugins.AdminApi plugin
 * (https://github.com/palchrb/Impostor branch
 * claude/fix-impostor-game-discovery-LQ6OP).
 *
 * Architecture: SSE-based real-time state.
 *
 *   1. On startup, take a one-shot snapshot via:
 *        GET /admin/games            → list of GameSummary
 *        GET /admin/games/{code}     → players per game (parallel)
 *      to populate in-memory state.
 *
 *   2. Subscribe to /admin/events (SSE) and apply incremental updates
 *      for game.created/destroyed/started/ended/privacyChanged and
 *      player.joined/left.
 *
 *   3. status() returns whatever in-memory state we currently hold —
 *      no per-call HTTP fetching.
 *
 *   4. If the SSE connection drops (server restart, network blip),
 *      reconnect with exponential backoff and re-snapshot.
 *
 * Authentication via the X-Admin-Key header when impostorAdminApiKey
 * is set. Leave empty if AdminApi is bound to localhost / restricted
 * by docker port mapping.
 */

import { logger } from "../logger";
import { GenericAdapter } from "./generic";
import type { ServiceConfig } from "../schemas";
import type { ServiceStatus } from "./types";

const SNAPSHOT_TIMEOUT_MS = 5_000;
const RECONNECT_INITIAL_MS = 1_000;
const RECONNECT_MAX_MS = 60_000;

const MAP_NAMES: Record<number, string> = {
  0: "The Skeld",
  1: "Mira HQ",
  2: "Polus",
  3: "Dleks",
  4: "Airship",
  5: "The Fungle",
};

interface GameSummary {
  code: string;
  hostName: string | null;
  displayName: string | null;
  playerCount: number;
  maxPlayers: number;
  state: string;
  isPublic: boolean;
  numImpostors: number;
  mapId: number;
  gameMode: string;
}

interface PlayerInfo {
  clientId: number;
  name: string;
  isHost: boolean;
}

interface GameDetail {
  summary: GameSummary;
  players: PlayerInfo[];
}

interface GameState extends GameSummary {
  players: PlayerInfo[];
}

export class ImpostorAdapter extends GenericAdapter {
  private readonly apiUrl: string;
  private readonly apiKey: string | null;
  private readonly showPrivateGames: boolean;
  private readonly games = new Map<string, GameState>();
  private connected = false;
  private running = true;
  private abortController: AbortController | null = null;
  private reconnectAttempt = 0;

  constructor(config: ServiceConfig) {
    super(config);
    this.apiUrl =
      config.impostorAdminApiUrl ?? `http://${config.container}:8081`;
    this.apiKey = config.impostorAdminApiKey ?? null;
    // Default false respects the "private" toggle set by the lobby
    // host — they explicitly said they don't want it public. Flip to
    // true in services.json for a family setup where siblings are
    // expected to be able to join each other's lobbies from the PWA.
    this.showPrivateGames = config.impostorShowPrivateGames ?? false;
    this.capabilities.add("players");
    void this.runLoop();
  }

  private authHeaders(): Record<string, string> {
    return this.apiKey ? { "X-Admin-Key": this.apiKey } : {};
  }

  private async fetchJson<T>(path: string, signal?: AbortSignal): Promise<T | null> {
    try {
      const res = await fetch(`${this.apiUrl}${path}`, {
        headers: this.authHeaders(),
        signal: signal ?? AbortSignal.timeout(SNAPSHOT_TIMEOUT_MS),
      });
      if (!res.ok) return null;
      return (await res.json()) as T;
    } catch {
      return null;
    }
  }

  /**
   * Fetch a single game's full detail via REST and merge into state.
   * Called after game.created (where the event payload is minimal) so
   * MaxPlayers, Map, NumImpostors etc. become accurate without waiting
   * for the next reconnect snapshot.
   */
  private async refreshGameDetail(code: string): Promise<void> {
    const detail = await this.fetchJson<GameDetail>(
      `/admin/games/${encodeURIComponent(code)}`,
    );
    if (!detail) return;
    const existing = this.games.get(code);
    const playersFromDetail = detail.players ?? [];
    this.games.set(code, {
      ...detail.summary,
      // Keep any players we already had from SSE events in case the
      // REST fetch happened mid-flight, but let REST be authoritative
      // when it has values.
      players: playersFromDetail.length > 0 ? playersFromDetail : (existing?.players ?? []),
    });
  }

  /** Re-populate `games` from a fresh REST snapshot. */
  private async snapshot(signal: AbortSignal): Promise<boolean> {
    const summaries = await this.fetchJson<GameSummary[]>("/admin/games", signal);
    if (!summaries) return false;
    const details = await Promise.all(
      summaries.map((g) =>
        this.fetchJson<GameDetail>(
          `/admin/games/${encodeURIComponent(g.code)}`,
          signal,
        ),
      ),
    );
    this.games.clear();
    for (let i = 0; i < summaries.length; i++) {
      const s = summaries[i]!;
      const d = details[i];
      this.games.set(s.code, { ...s, players: d?.players ?? [] });
    }
    return true;
  }

  /** Long-running loop: snapshot + subscribe to SSE, reconnect on failure. */
  private async runLoop(): Promise<void> {
    while (this.running) {
      this.abortController = new AbortController();
      try {
        const ok = await this.snapshot(this.abortController.signal);
        if (!ok) throw new Error("snapshot failed");
        await this.subscribe(this.abortController.signal);
        // subscribe() returns when the stream ends cleanly — treat as a
        // disconnect and reconnect after a short delay.
      } catch (err) {
        if (!this.running) break;
        logger().debug(
          { err: (err as Error).message, service: this.id },
          "impostor adapter SSE error — reconnecting",
        );
      }

      this.connected = false;
      if (!this.running) break;

      const delay = Math.min(
        RECONNECT_MAX_MS,
        RECONNECT_INITIAL_MS * 2 ** Math.min(this.reconnectAttempt, 6),
      );
      this.reconnectAttempt++;
      await new Promise((r) => setTimeout(r, delay));
    }
  }

  private async subscribe(signal: AbortSignal): Promise<void> {
    const res = await fetch(`${this.apiUrl}/admin/events`, {
      headers: { ...this.authHeaders(), Accept: "text/event-stream" },
      signal,
    });
    if (!res.ok || !res.body) {
      throw new Error(`SSE subscribe failed: HTTP ${res.status}`);
    }
    this.connected = true;
    this.reconnectAttempt = 0;
    logger().info({ service: this.id }, "impostor SSE connected");

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    while (this.running) {
      const { done, value } = await reader.read();
      if (done) return;
      buffer += decoder.decode(value, { stream: true });
      // SSE event blocks are separated by blank line.
      const blocks = buffer.split(/\r?\n\r?\n/);
      buffer = blocks.pop() ?? "";
      for (const block of blocks) this.processBlock(block);
    }
  }

  private processBlock(block: string): void {
    let eventType = "";
    let dataStr = "";
    for (const line of block.split(/\r?\n/)) {
      if (line.startsWith("event: ")) eventType = line.slice(7).trim();
      else if (line.startsWith("data: ")) dataStr += line.slice(6);
    }
    if (!eventType || !dataStr) return;
    let parsed: { type?: string; data?: Record<string, unknown> };
    try {
      parsed = JSON.parse(dataStr);
    } catch {
      return;
    }
    const payload = parsed.data ?? {};
    this.handleEvent(eventType, payload);
  }

  private handleEvent(type: string, data: Record<string, unknown>): void {
    const code = typeof data["code"] === "string" ? (data["code"] as string) : null;

    switch (type) {
      case "hello":
        // Initial subscription confirmation — no-op, snapshot already fresh.
        return;

      case "game.created": {
        if (!code) return;
        if (!this.games.has(code)) {
          // The game.created event only carries {code, hostName, hostIp}
          // from the plugin. Map, MaxPlayers, NumImpostors and GameMode
          // all live in game.Options on the server side and require a
          // REST fetch. Stub an entry now so subsequent player.joined
          // events have somewhere to land, then refresh from /admin/games/{code}.
          this.games.set(code, {
            code,
            hostName: (data["hostName"] as string) ?? null,
            displayName: null,
            playerCount: 0,
            maxPlayers: 10,
            state: "NotStarted",
            isPublic: false,
            numImpostors: 0,
            mapId: 0,
            gameMode: "Normal",
            players: [],
          });
          void this.refreshGameDetail(code);
        }
        return;
      }

      case "game.destroyed": {
        if (code) this.games.delete(code);
        return;
      }

      case "game.started": {
        const g = code ? this.games.get(code) : null;
        if (g) g.state = "Started";
        return;
      }

      case "game.ended": {
        const g = code ? this.games.get(code) : null;
        if (g) g.state = "Ended";
        return;
      }

      case "game.privacyChanged": {
        const g = code ? this.games.get(code) : null;
        if (g) g.isPublic = data["isPublic"] === true;
        return;
      }

      case "player.joined": {
        const g = code ? this.games.get(code) : null;
        if (!g) return;
        const clientId = data["clientId"] as number;
        const name = (data["name"] as string) ?? "";
        const isHost = data["isHost"] === true;
        if (!g.players.some((p) => p.clientId === clientId)) {
          g.players.push({ clientId, name, isHost });
        }
        g.playerCount = g.players.length;
        return;
      }

      case "player.left": {
        const g = code ? this.games.get(code) : null;
        if (!g) return;
        const clientId = data["clientId"] as number;
        g.players = g.players.filter((p) => p.clientId !== clientId);
        g.playerCount = g.players.length;
        return;
      }

      case "game.starting": {
        const g = code ? this.games.get(code) : null;
        if (g) g.state = "Starting";
        return;
      }

      case "game.hostChanged": {
        const g = code ? this.games.get(code) : null;
        if (!g) return;
        const newName = (data["newHostName"] as string) ?? null;
        if (newName) g.hostName = newName;
        // Update isHost flags on the players list so the UI can reflect
        // the migration without waiting for the next snapshot.
        const newId = data["newHostClientId"];
        for (const p of g.players) p.isHost = p.clientId === newId;
        return;
      }

      case "game.optionsChanged": {
        const g = code ? this.games.get(code) : null;
        if (!g) return;
        if (typeof data["maxPlayers"] === "number") g.maxPlayers = data["maxPlayers"] as number;
        if (typeof data["numImpostors"] === "number") g.numImpostors = data["numImpostors"] as number;
        if (typeof data["mapId"] === "number") g.mapId = data["mapId"] as number;
        if (typeof data["gameMode"] === "string") g.gameMode = data["gameMode"] as string;
        return;
      }

      // These events are accepted but not surfaced in status() yet.
      // Listing them explicitly (rather than falling through to the
      // default) documents what the plugin emits and keeps future
      // logging around unknown events meaningful.
      case "client.connected":
      case "player.joining.rejected":
      case "chat":
      case "player.murder":
      case "player.exiled":
      case "player.voted":
      case "meeting.called":
      case "meeting.started":
      case "meeting.ended":
        return;

      default:
        return;
    }
  }

  override async status(): Promise<ServiceStatus> {
    const base = await super.status();
    if (!base.running) return base;

    // All games contribute to player count / aggregate stats — the
    // privacy flag only affects whether individual codes are exposed
    // to the lobby list in the PWA.
    const gamesArr = [...this.games.values()];
    const allNames = gamesArr.flatMap((g) => g.players.map((p) => p.name));
    const visibleGames = this.showPrivateGames
      ? gamesArr
      : gamesArr.filter((g) => g.isPublic);
    const gamesView = visibleGames.map((g) => ({
      code: g.code,
      host: g.hostName,
      players: g.players.map((p) => p.name),
      playerCount: g.playerCount,
      maxPlayers: g.maxPlayers,
      isPublic: g.isPublic,
      state: g.state,
      map: MAP_NAMES[g.mapId] ?? `Map ${g.mapId}`,
      impostors: g.numImpostors,
    }));
    const privateHidden = gamesArr.length - visibleGames.length;

    return {
      running: true,
      players: [...new Set(allNames.filter(Boolean))],
      details: {
        ...base.details,
        adminApiConnected: this.connected,
        gameCount: gamesArr.length,
        publicGames: gamesArr.filter((g) => g.isPublic).length,
        privateGamesHidden: privateHidden,
        totalPlayers: gamesArr.reduce((s, g) => s + g.playerCount, 0),
        games: gamesView,
      },
    };
  }

  async dispose(): Promise<void> {
    this.running = false;
    this.abortController?.abort();
    this.games.clear();
  }
}
