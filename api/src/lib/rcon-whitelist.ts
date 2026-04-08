/**
 * RCON command whitelist.
 *
 * The admin `/api/services/:id/command/:cmd` route is already protected
 * by the admin session gate, so the threat model here is narrow: we
 * want defence-in-depth so that if anything else ever proxies into the
 * RCON send path without a gate, only safe commands get through.
 *
 * The whitelist matches on the first word of the command (case-insensitive);
 * the rest of the string is passed through as arguments. This is enough
 * to block arbitrary script-execution style commands while still allowing
 * the typical admin ops the dashboard needs.
 *
 * We deliberately allow /plugin-style extensions to run through the
 * dedicated high-level routes (whitelist/add, op/deop, backup, worlds
 * switching). Those routes build their own RCON strings in code and do
 * NOT go through this whitelist, so adding a command here is only ever
 * needed when you want the generic /command text input to accept it.
 */

const ALLOWED: ReadonlySet<string> = new Set([
  // informational
  "list",
  "help",
  "seed",
  "tps",

  // world / time / weather (harmless globals)
  "time",
  "weather",
  "difficulty",
  "gamemode",
  "gamerule",

  // player ops (admin typically needs these)
  "kick",
  "ban",
  "pardon",
  "whitelist",
  "op",
  "deop",
  "tp",
  "teleport",
  "give",
  "clear",
  "effect",
  "xp",

  // chat
  "say",
  "me",
  "msg",
  "tell",

  // meta
  "save-all",
  "save-on",
  "save-off",
]);

export function isRconCommandAllowed(raw: string): boolean {
  const trimmed = raw.trim();
  if (!trimmed) return false;
  // Commands may start with a leading slash; strip it.
  const body = trimmed.startsWith("/") ? trimmed.slice(1) : trimmed;
  const firstWord = body.split(/\s+/u, 1)[0] ?? "";
  if (!firstWord) return false;
  return ALLOWED.has(firstWord.toLowerCase());
}

/** Exposed for tests. */
export function listAllowedRconCommands(): readonly string[] {
  return Array.from(ALLOWED).sort();
}
