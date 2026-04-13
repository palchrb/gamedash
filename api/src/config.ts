/**
 * Typed application configuration parsed from environment variables.
 *
 * All env vars are validated at process start via Zod. Invalid or missing
 * required vars cause an immediate crash with a clear error message rather
 * than a silent misconfiguration at runtime.
 */

import "dotenv/config";
import { z } from "zod";

const booleanString = z
  .string()
  .transform((v) => v.toLowerCase() === "true" || v === "1")
  .pipe(z.boolean());

const positiveInt = z
  .string()
  .regex(/^\d+$/u, "must be a non-negative integer")
  .transform((v) => parseInt(v, 10));

const ConfigSchema = z.object({
  // ── HTTP ───────────────────────────────────────────────────────────────
  API_PORT: positiveInt.default("3000"),
  TRUST_PROXY: z.string().default("loopback"),

  // ── Logging ────────────────────────────────────────────────────────────
  LOG_LEVEL: z
    .enum(["fatal", "error", "warn", "info", "debug", "trace", "silent"])
    .default("info"),
  LOG_PRETTY: booleanString.optional().default("false"),

  // ── Storage paths (inside the /data mount) ───────────────────────────
  DATA_DIR: z.string().default("/data"),
  SERVICES_FILE: z.string().optional(),
  USERS_FILE: z.string().optional(),
  FIREWALL_RULES_FILE: z.string().optional(),
  STATS_FILE: z.string().optional(),
  AUDIT_LOG: z.string().optional(),
  ADMIN_CREDENTIALS_FILE: z.string().optional(),
  ADMIN_SESSIONS_FILE: z.string().optional(),
  KNOCK_SESSIONS_FILE: z.string().optional(),
  UPLOADS_DIR: z.string().optional(),

  // ── Service registry ──────────────────────────────────────────────────
  DEFAULT_SERVICE_ID: z.string().default("mc1"),

  // ── Knock (per-user PWA) ───────────────────────────────────────────────
  KNOCK_USER_TTL_HOURS: positiveInt.default("24"),
  KNOCK_IGNORE_RANGES: z.string().default("100.64.0.0/10"),

  // ── i18n ───────────────────────────────────────────────────────────────
  DEFAULT_LOCALE: z.string().default("en"),

  // ── UFW sidecar ───────────────────────────────────────────────────────
  UFW_SIDECAR_URL: z.string().default("http://ufw-sidecar:9090"),
  UFW_SIDECAR_TOKEN: z.string().optional(),

  // ── Admin passkey auth (Phase 1) ───────────────────────────────────────
  ADMIN_RP_ID: z.string().default("localhost"),
  ADMIN_RP_NAME: z.string().default("GameDash"),
  ADMIN_ORIGIN: z.string().default("http://localhost:3000"),
  ADMIN_SESSION_TTL_HOURS: positiveInt.default("12"),
  ADMIN_REAUTH_AFTER_HOURS: positiveInt.default("168"),
  ADMIN_BOOTSTRAP_WINDOW_MINUTES: positiveInt.default("15"),

  // ── Knock passkey (Phase 3, optional) ──────────────────────────────────
  KNOCK_REQUIRE_PASSKEY: booleanString.optional().default("false"),
  KNOCK_PASSKEY_REAUTH_HOURS: positiveInt.default("720"),
  KNOCK_REGISTRATION_TTL_HOURS: positiveInt.default("24"),

  // ── Audit log rotation (Phase 4) ───────────────────────────────────────
  AUDIT_LOG_MAX_BYTES: positiveInt.default("10485760"), // 10 MiB
  AUDIT_LOG_MAX_FILES: positiveInt.default("5"),

  // ── Misc ──────────────────────────────────────────────────────────────
  NODE_ENV: z.enum(["development", "production", "test"]).default("production"),
});

export type Config = z.infer<typeof ConfigSchema> & {
  servicesFile: string;
  usersFile: string;
  firewallRulesFile: string;
  statsFile: string;
  auditLog: string;
  adminCredentialsFile: string;
  adminSessionsFile: string;
  knockSessionsFile: string;
  uploadsDir: string;
  knockIgnoreRanges: ReadonlyArray<{ ip32: number; mask: number }>;
};

function parseCidrList(raw: string): Array<{ ip32: number; mask: number }> {
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((cidr) => {
      const [net, bits] = cidr.split("/");
      if (!net) throw new Error(`invalid CIDR "${cidr}"`);
      const parts = net.split(".").map(Number);
      if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) {
        throw new Error(`invalid CIDR "${cidr}"`);
      }
      const ip32 =
        ((parts[0]! << 24) | (parts[1]! << 16) | (parts[2]! << 8) | parts[3]!) >>> 0;
      const maskBits = bits ? parseInt(bits, 10) : 32;
      if (Number.isNaN(maskBits) || maskBits < 0 || maskBits > 32) {
        throw new Error(`invalid CIDR "${cidr}"`);
      }
      const mask = maskBits === 0 ? 0 : (~0 << (32 - maskBits)) >>> 0;
      return { ip32, mask };
    });
}

function join(dir: string, name: string): string {
  return dir.endsWith("/") ? `${dir}${name}` : `${dir}/${name}`;
}

export function loadConfig(): Config {
  const parsed = ConfigSchema.safeParse(process.env);
  if (!parsed.success) {
    const errs = parsed.error.issues
      .map((i) => `  - ${i.path.join(".")}: ${i.message}`)
      .join("\n");
    throw new Error(`Invalid configuration:\n${errs}`);
  }
  const c = parsed.data;
  const dataDir = c.DATA_DIR;
  return {
    ...c,
    servicesFile: c.SERVICES_FILE ?? join(dataDir, "services.json"),
    usersFile: c.USERS_FILE ?? join(dataDir, "users.json"),
    firewallRulesFile: c.FIREWALL_RULES_FILE ?? join(dataDir, "firewall-rules.json"),
    statsFile: c.STATS_FILE ?? join(dataDir, "stats.json"),
    auditLog: c.AUDIT_LOG ?? join(dataDir, "audit.log"),
    adminCredentialsFile: c.ADMIN_CREDENTIALS_FILE ?? join(dataDir, "admin-credentials.json"),
    adminSessionsFile: c.ADMIN_SESSIONS_FILE ?? join(dataDir, "admin-sessions.json"),
    knockSessionsFile: c.KNOCK_SESSIONS_FILE ?? join(dataDir, "knock-sessions.json"),
    uploadsDir: c.UPLOADS_DIR ?? join(dataDir, "uploads"),
    knockIgnoreRanges: parseCidrList(c.KNOCK_IGNORE_RANGES),
  };
}

// Singleton accessor — initialised lazily so tests can set env before import.
let _config: Config | null = null;
export function config(): Config {
  if (!_config) _config = loadConfig();
  return _config;
}

/** Reset the cached config — test-only. */
export function resetConfigForTests(): void {
  _config = null;
}
