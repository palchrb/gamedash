/**
 * Single source of truth for all JSON datastructures on disk + HTTP boundaries.
 *
 * Zod schemas double as runtime validators (crash early on corrupt files)
 * and as TS type generators via z.infer<>. Any time we load one of these
 * files, we parse it through the schema; any time we write, we know the
 * shape is correct because TypeScript enforces it.
 */

import { z } from "zod";

// ── Shared primitives ──────────────────────────────────────────────────

export const PortSpecSchema = z.object({
  port: z.string().regex(/^\d+$/u, "port must be a numeric string"),
  proto: z.enum(["tcp", "udp"]),
});
export type PortSpec = z.infer<typeof PortSpecSchema>;

export const IsoTimestampSchema = z
  .string()
  .datetime({ offset: true, message: "must be an ISO-8601 timestamp" });

// ── services.json ──────────────────────────────────────────────────────

export const ServiceConfigSchema = z.object({
  id: z.string().min(1).regex(/^[a-z0-9_-]+$/u, "id must be lowercase alphanumeric"),
  name: z.string().min(1),
  type: z.enum(["minecraft", "generic"]),
  container: z.string().min(1),
  ports: z.array(PortSpecSchema).min(1),
  dataDir: z.string().optional(),
  logFile: z.string().optional(),
  rcon: z
    .object({
      host: z.string().optional(),
      port: z.number().int().positive().optional(),
      password: z.string().optional(),
      passwordEnv: z.string().optional(),
    })
    .optional(),
  backupsDir: z.string().optional(),
  worldsDir: z.string().optional(),
  activeWorldDir: z.string().optional(),
  currentWorldFile: z.string().optional(),
});
export type ServiceConfig = z.infer<typeof ServiceConfigSchema>;

export const ServicesFileSchema = z.object({
  services: z.array(ServiceConfigSchema),
});
export type ServicesFile = z.infer<typeof ServicesFileSchema>;

// ── users.json ─────────────────────────────────────────────────────────

export const UserHistoryEntrySchema = z.object({
  ip: z.string(),
  at: IsoTimestampSchema,
  services: z.array(z.string()),
  ua: z.string().nullable().optional(),
  kind: z.enum(["knock", "renew", "revoke", "auto_expire"]),
});
export type UserHistoryEntry = z.infer<typeof UserHistoryEntrySchema>;

export const KnockCredentialSchema = z.object({
  id: z.string(),
  publicKey: z.string(), // base64url
  counter: z.number().int().nonnegative(),
  transports: z.array(z.string()).optional(),
  deviceLabel: z.string().optional(),
  createdAt: IsoTimestampSchema,
  lastUsedAt: IsoTimestampSchema.nullable(),
});
export type KnockCredential = z.infer<typeof KnockCredentialSchema>;

export const UserRecordSchema = z.object({
  id: z.string(),
  name: z.string(),
  tokenHash: z.string(), // sha-256 hex of the url token, never stored in clear
  allowedServices: z.array(z.string()),
  locale: z.string().nullable(),
  createdAt: IsoTimestampSchema,
  history: z.array(UserHistoryEntrySchema),
  credentials: z.array(KnockCredentialSchema).default([]),
  registrationOpenUntil: IsoTimestampSchema.nullable().default(null),
});
export type UserRecord = z.infer<typeof UserRecordSchema>;

export const UsersFileSchema = z.object({
  users: z.array(UserRecordSchema),
});
export type UsersFile = z.infer<typeof UsersFileSchema>;

// ── firewall-rules.json ────────────────────────────────────────────────

export const RuleServiceSchema = z.object({
  id: z.string(),
  ports: z.array(PortSpecSchema),
});
export type RuleService = z.infer<typeof RuleServiceSchema>;

export const FirewallRuleSchema = z.object({
  ip: z.string(),
  addedAt: IsoTimestampSchema,
  expiresAt: IsoTimestampSchema.nullable().optional(),
  label: z.string().default(""),
  userId: z.string().nullable().optional(),
  services: z.array(RuleServiceSchema),
});
export type FirewallRule = z.infer<typeof FirewallRuleSchema>;

export const FirewallRulesFileSchema = z.object({
  rules: z.array(FirewallRuleSchema),
});
export type FirewallRulesFile = z.infer<typeof FirewallRulesFileSchema>;

// ── stats.json ─────────────────────────────────────────────────────────

export const UserStatsSchema = z.object({
  totalSeconds: z.number().int().nonnegative().default(0),
  perService: z.record(z.string(), z.number().int().nonnegative()).default({}),
  perDay: z
    .record(z.string(), z.record(z.string(), z.number().int().nonnegative()))
    .default({}),
  lastPlayedAt: IsoTimestampSchema.nullable().default(null),
  currentSessions: z.record(z.string(), IsoTimestampSchema).default({}),
});
export type UserStats = z.infer<typeof UserStatsSchema>;

export const StatsFileSchema = z.object({
  users: z.record(z.string(), UserStatsSchema).default({}),
});
export type StatsFile = z.infer<typeof StatsFileSchema>;

// ── admin-credentials.json ─────────────────────────────────────────────

export const AdminCredentialSchema = z.object({
  id: z.string(), // base64url credential id
  publicKey: z.string(), // base64url
  counter: z.number().int().nonnegative(),
  transports: z.array(z.string()).optional(),
  deviceLabel: z.string().optional(),
  createdAt: IsoTimestampSchema,
  lastUsedAt: IsoTimestampSchema.nullable(),
});
export type AdminCredential = z.infer<typeof AdminCredentialSchema>;

export const AdminRecordSchema = z.object({
  id: z.string(),
  name: z.string(),
  credentials: z.array(AdminCredentialSchema),
  createdAt: IsoTimestampSchema,
});
export type AdminRecord = z.infer<typeof AdminRecordSchema>;

export const AdminCredentialsFileSchema = z.object({
  admins: z.array(AdminRecordSchema).default([]),
});
export type AdminCredentialsFile = z.infer<typeof AdminCredentialsFileSchema>;

// ── admin-sessions.json ────────────────────────────────────────────────

export const AdminSessionSchema = z.object({
  idHash: z.string(), // sha-256 of the opaque session id (cookie value)
  adminId: z.string(),
  createdAt: IsoTimestampSchema,
  expiresAt: IsoTimestampSchema,
  reauthAfter: IsoTimestampSchema,
  lastSeenAt: IsoTimestampSchema,
  ip: z.string(),
  ua: z.string().nullable(),
});
export type AdminSession = z.infer<typeof AdminSessionSchema>;

export const AdminSessionsFileSchema = z.object({
  sessions: z.array(AdminSessionSchema).default([]),
});
export type AdminSessionsFile = z.infer<typeof AdminSessionsFileSchema>;

// ── knock-sessions.json (Phase 3) ──────────────────────────────────────

export const KnockSessionSchema = z.object({
  idHash: z.string(),
  userId: z.string(),
  createdAt: IsoTimestampSchema,
  expiresAt: IsoTimestampSchema,
  lastSeenAt: IsoTimestampSchema,
  ip: z.string(),
  ua: z.string().nullable(),
});
export type KnockSession = z.infer<typeof KnockSessionSchema>;

export const KnockSessionsFileSchema = z.object({
  sessions: z.array(KnockSessionSchema).default([]),
});
export type KnockSessionsFile = z.infer<typeof KnockSessionsFileSchema>;

// ── HTTP request bodies ────────────────────────────────────────────────

export const CreateUserBodySchema = z.object({
  name: z.string().min(1).max(64),
  allowedServices: z.array(z.string()).default([]),
  locale: z.string().nullable().optional(),
});
export type CreateUserBody = z.infer<typeof CreateUserBodySchema>;

export const UpdateUserBodySchema = z.object({
  name: z.string().min(1).max(64).optional(),
  allowedServices: z.array(z.string()).optional(),
  locale: z.string().nullable().optional(),
});
export type UpdateUserBody = z.infer<typeof UpdateUserBodySchema>;

export const FirewallAddBodySchema = z.object({
  ip: z.string(),
  label: z.string().optional(),
  services: z.array(z.string()).optional(),
});
export type FirewallAddBody = z.infer<typeof FirewallAddBodySchema>;

export const FirewallRemoveBodySchema = z.object({
  ip: z.string(),
});
export type FirewallRemoveBody = z.infer<typeof FirewallRemoveBodySchema>;

export const KnockBodySchema = z.object({
  services: z.union([z.literal("all"), z.array(z.string()), z.string()]).optional(),
  force: z.boolean().optional(),
});
export type KnockBody = z.infer<typeof KnockBodySchema>;

export const PlayerBodySchema = z.object({
  player: z.string().min(1).max(32).regex(/^[A-Za-z0-9_]+$/u),
});
export type PlayerBody = z.infer<typeof PlayerBodySchema>;
