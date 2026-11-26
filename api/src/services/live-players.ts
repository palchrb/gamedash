/**
 * Best-effort live player info from every adapter with the "players"
 * capability: player names (RCON / TShock / Impostor AdminApi) and, for
 * adapters that expose them (currently Impostor), the open game lobbies.
 *
 * Shared by the player PWA's /u/:token/active and the admin
 * /admin/api/active-sessions so both "Who is playing now" panels show
 * the same information.
 */

import { registry } from "./registry";

export interface LivePlayerInfo {
  playersByService: Record<string, string[]>;
  gamesByService: Record<string, unknown[]>;
}

export async function collectLivePlayerInfo(): Promise<LivePlayerInfo> {
  const playersByService: Record<string, string[]> = {};
  const gamesByService: Record<string, unknown[]> = {};
  await Promise.all(
    [...registry().services.values()]
      .filter((svc) => svc.hasCapability("players"))
      .map(async (svc) => {
        try {
          const st = await svc.status();
          if (st.players.length > 0) playersByService[svc.id] = st.players;
          const maybeGames = (st.details as { games?: unknown[] } | undefined)?.games;
          if (Array.isArray(maybeGames) && maybeGames.length > 0) {
            gamesByService[svc.id] = maybeGames;
          }
        } catch {
          // ignore — player fetch is best-effort
        }
      }),
  );
  return { playersByService, gamesByService };
}
