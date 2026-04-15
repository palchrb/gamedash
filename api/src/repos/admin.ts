/**
 * Admin credentials + sessions repositories.
 *
 * Two files:
 *   admin-credentials.json — durable list of admins and their WebAuthn
 *                            credentials. Mutated on register / remove.
 *   admin-sessions.json    — ephemeral list of issued session ids
 *                            (stored as SHA-256 hashes). Cleaned up when
 *                            a session expires or is revoked.
 *
 * The split isolates hot state (sessions churn every few hours) from
 * cold state (credentials rarely change), so session cleanup never
 * touches the credentials file.
 */

import * as crypto from "node:crypto";
import { config } from "../config";
import { readJson, withLock, writeJson } from "../lib/atomic-file";
import { sha256Hex, generateToken, constantTimeEqualHex } from "../lib/hash";
import {
  type AdminCredentialsFile,
  AdminCredentialsFileSchema,
  type AdminRecord,
  type WebAuthnCredential,
  type AdminSession,
  type AdminSessionsFile,
  AdminSessionsFileSchema,
} from "../schemas";

// ── Credentials ────────────────────────────────────────────────────────

function credsPath(): string {
  return config().adminCredentialsFile;
}

export async function loadAdminCredentials(): Promise<AdminCredentialsFile> {
  return readJson(credsPath(), AdminCredentialsFileSchema, { admins: [] });
}

export async function saveAdminCredentials(data: AdminCredentialsFile): Promise<void> {
  await writeJson(credsPath(), AdminCredentialsFileSchema, data);
}

export async function mutateAdminCredentials<T>(
  fn: (draft: AdminCredentialsFile) => Promise<T> | T,
): Promise<T> {
  return withLock(`admin-creds:${credsPath()}`, async () => {
    const draft = await loadAdminCredentials();
    const result = await fn(draft);
    await saveAdminCredentials(draft);
    return result;
  });
}

export async function findAdminById(id: string): Promise<AdminRecord | null> {
  const data = await loadAdminCredentials();
  return data.admins.find((a) => a.id === id) ?? null;
}

export async function findAdminByCredentialId(
  credentialId: string,
): Promise<{ admin: AdminRecord; credential: WebAuthnCredential } | null> {
  const data = await loadAdminCredentials();
  for (const admin of data.admins) {
    const credential = admin.credentials.find((c) => c.id === credentialId);
    if (credential) return { admin, credential };
  }
  return null;
}

export async function hasAnyAdmin(): Promise<boolean> {
  const data = await loadAdminCredentials();
  return data.admins.some((a) => a.credentials.length > 0);
}

export async function createAdmin(name: string): Promise<AdminRecord> {
  return mutateAdminCredentials((draft) => {
    const now = new Date().toISOString();
    const id = `a_${Date.now().toString(36)}_${crypto.randomBytes(6).toString("hex")}`;
    const record: AdminRecord = {
      id,
      name,
      credentials: [],
      createdAt: now,
    };
    draft.admins.push(record);
    return record;
  });
}

/** Create a new admin with an invite token. Returns the plaintext token (shown once). */
export async function createAdminWithInvite(name: string): Promise<{ admin: AdminRecord; plainInviteToken: string }> {
  const plainInviteToken = generateToken(32);
  const inviteTokenHash = sha256Hex(plainInviteToken);
  const admin = await mutateAdminCredentials((draft) => {
    if (draft.admins.some((a) => a.name.toLowerCase() === name.toLowerCase())) {
      throw new Error("An admin with that name already exists");
    }
    const now = new Date().toISOString();
    const id = `a_${Date.now().toString(36)}_${crypto.randomBytes(6).toString("hex")}`;
    const record: AdminRecord = {
      id,
      name,
      credentials: [],
      createdAt: now,
      inviteTokenHash,
    };
    draft.admins.push(record);
    return record;
  });
  return { admin, plainInviteToken };
}

/** Find an admin by invite token. Returns null if no match or token is missing. */
export async function findAdminByInviteToken(token: string): Promise<AdminRecord | null> {
  if (!token) return null;
  const candidateHash = sha256Hex(token);
  const data = await loadAdminCredentials();
  for (const admin of data.admins) {
    if (admin.inviteTokenHash && constantTimeEqualHex(admin.inviteTokenHash, candidateHash)) {
      return admin;
    }
  }
  return null;
}

/** Clear the invite token after successful registration. */
export async function clearInviteToken(adminId: string): Promise<void> {
  await mutateAdminCredentials((draft) => {
    const admin = draft.admins.find((a) => a.id === adminId);
    if (admin) admin.inviteTokenHash = null;
  });
}

/** List all admins (public projection — no invite token hashes). */
export async function listAdmins(): Promise<Array<{ id: string; name: string; createdAt: string; credentialCount: number }>> {
  const data = await loadAdminCredentials();
  return data.admins.map((a) => ({
    id: a.id,
    name: a.name,
    createdAt: a.createdAt,
    credentialCount: a.credentials.length,
  }));
}

/** Delete an admin and all their sessions. */
export async function deleteAdmin(adminId: string): Promise<boolean> {
  return mutateAdminCredentials((draft) => {
    const idx = draft.admins.findIndex((a) => a.id === adminId);
    if (idx < 0) return false;
    draft.admins.splice(idx, 1);
    return true;
  });
}

export async function addAdminCredential(
  adminId: string,
  credential: WebAuthnCredential,
): Promise<void> {
  await mutateAdminCredentials((draft) => {
    const admin = draft.admins.find((a) => a.id === adminId);
    if (!admin) throw new Error("Admin not found");
    admin.credentials.push(credential);
  });
}

export async function removeAdminCredential(
  adminId: string,
  credentialId: string,
): Promise<void> {
  await mutateAdminCredentials((draft) => {
    const admin = draft.admins.find((a) => a.id === adminId);
    if (!admin) return;
    admin.credentials = admin.credentials.filter((c) => c.id !== credentialId);
  });
}

export async function updateAdminLocale(
  adminId: string,
  locale: string | null,
): Promise<void> {
  await mutateAdminCredentials((draft) => {
    const admin = draft.admins.find((a) => a.id === adminId);
    if (!admin) throw new Error("Admin not found");
    admin.locale = locale;
  });
}

export async function updateAdminCredentialCounter(
  adminId: string,
  credentialId: string,
  counter: number,
): Promise<void> {
  await mutateAdminCredentials((draft) => {
    const admin = draft.admins.find((a) => a.id === adminId);
    if (!admin) return;
    const cred = admin.credentials.find((c) => c.id === credentialId);
    if (!cred) return;
    cred.counter = counter;
    cred.lastUsedAt = new Date().toISOString();
  });
}

// ── Sessions ───────────────────────────────────────────────────────────

function sessionsPath(): string {
  return config().adminSessionsFile;
}

export async function loadAdminSessions(): Promise<AdminSessionsFile> {
  return readJson(sessionsPath(), AdminSessionsFileSchema, { sessions: [] });
}

export async function saveAdminSessions(data: AdminSessionsFile): Promise<void> {
  await writeJson(sessionsPath(), AdminSessionsFileSchema, data);
}

export async function mutateAdminSessions<T>(
  fn: (draft: AdminSessionsFile) => Promise<T> | T,
): Promise<T> {
  return withLock(`admin-sessions:${sessionsPath()}`, async () => {
    const draft = await loadAdminSessions();
    const result = await fn(draft);
    await saveAdminSessions(draft);
    return result;
  });
}

export async function addAdminSession(session: AdminSession): Promise<void> {
  await mutateAdminSessions((draft) => {
    draft.sessions.push(session);
  });
}

export async function findAdminSessionByIdHash(
  idHash: string,
): Promise<AdminSession | null> {
  const data = await loadAdminSessions();
  return data.sessions.find((s) => s.idHash === idHash) ?? null;
}

export async function touchAdminSession(idHash: string): Promise<void> {
  await mutateAdminSessions((draft) => {
    const s = draft.sessions.find((x) => x.idHash === idHash);
    if (!s) return;
    s.lastSeenAt = new Date().toISOString();
  });
}

export async function deleteAdminSessionByIdHash(idHash: string): Promise<void> {
  await mutateAdminSessions((draft) => {
    draft.sessions = draft.sessions.filter((s) => s.idHash !== idHash);
  });
}

export async function deleteAdminSessionsForAdmin(adminId: string): Promise<number> {
  let removed = 0;
  await mutateAdminSessions((draft) => {
    const before = draft.sessions.length;
    draft.sessions = draft.sessions.filter((s) => s.adminId !== adminId);
    removed = before - draft.sessions.length;
  });
  return removed;
}

export async function sweepExpiredSessions(): Promise<number> {
  let removed = 0;
  const now = Date.now();
  await mutateAdminSessions((draft) => {
    const before = draft.sessions.length;
    draft.sessions = draft.sessions.filter(
      (s) => new Date(s.expiresAt).getTime() > now,
    );
    removed = before - draft.sessions.length;
  });
  return removed;
}

export function hashSessionId(plain: string): string {
  return sha256Hex(plain);
}
