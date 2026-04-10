/**
 * Users repository — per-child knock tokens, WebAuthn credentials (Phase 3),
 * access history. Atomic writes under a per-file mutex.
 *
 * Tokens are NEVER stored in clear. We keep only SHA-256 hashes on disk.
 * The plaintext token is returned exactly once from createUser/rotateToken
 * and must be delivered to the user via an out-of-band channel (the admin
 * UI surfaces a one-time copy-link dialog).
 */

import { config } from "../config";
import { sha256Hex, generateToken, constantTimeEqualHex } from "../lib/hash";
import { readJson, withLock, writeJson } from "../lib/atomic-file";
import {
  type UserRecord,
  type UsersFile,
  UsersFileSchema,
  type UserHistoryEntry,
  type WebAuthnCredential,
} from "../schemas";

const HISTORY_MAX = 20;

function filePath(): string {
  return config().usersFile;
}

function newUserId(name: string): string {
  const safe = (name || "user")
    .toLowerCase()
    .replace(/[^a-z0-9]+/gu, "_")
    .slice(0, 16);
  const suffix = generateToken(3).replace(/[-_]/gu, "x");
  return `u_${safe}_${suffix}`;
}

export async function loadUsers(): Promise<UsersFile> {
  return readJson(filePath(), UsersFileSchema, { users: [] });
}

export async function saveUsers(data: UsersFile): Promise<void> {
  await writeJson(filePath(), UsersFileSchema, data);
}

export async function mutateUsers<T>(
  fn: (draft: UsersFile) => Promise<T> | T,
): Promise<T> {
  return withLock(`users:${filePath()}`, async () => {
    const draft = await loadUsers();
    const result = await fn(draft);
    await saveUsers(draft);
    return result;
  });
}

export async function listUsers(): Promise<UserRecord[]> {
  const data = await loadUsers();
  return data.users;
}

/** Publicly safe user projection — never includes the token hash. */
export interface PublicUser {
  id: string;
  name: string;
  allowedServices: string[];
  locale: string | null;
  createdAt: string;
  hasCredentials: boolean;
  registrationOpenUntil: string | null;
  credentials: Array<{
    id: string;
    deviceLabel: string | null;
    createdAt: string;
    lastUsedAt: string | null;
  }>;
}

export function toPublic(u: UserRecord): PublicUser {
  return {
    id: u.id,
    name: u.name,
    allowedServices: u.allowedServices,
    locale: u.locale,
    createdAt: u.createdAt,
    hasCredentials: u.credentials.length > 0,
    registrationOpenUntil: u.registrationOpenUntil,
    credentials: u.credentials.map((c) => ({
      id: c.id,
      deviceLabel: c.deviceLabel ?? null,
      createdAt: c.createdAt,
      lastUsedAt: c.lastUsedAt,
    })),
  };
}

export async function findById(id: string): Promise<UserRecord | null> {
  const data = await loadUsers();
  return data.users.find((u) => u.id === id) ?? null;
}

export async function findUserByCredentialId(
  credentialId: string,
): Promise<{ user: UserRecord; credential: WebAuthnCredential } | null> {
  const data = await loadUsers();
  for (const user of data.users) {
    const credential = user.credentials.find((c) => c.id === credentialId);
    if (credential) return { user, credential };
  }
  return null;
}

export async function findByToken(token: string): Promise<UserRecord | null> {
  if (!token) return null;
  const candidateHash = sha256Hex(token);
  const data = await loadUsers();
  for (const u of data.users) {
    if (constantTimeEqualHex(u.tokenHash, candidateHash)) return u;
  }
  return null;
}

export interface CreatedUser {
  user: UserRecord;
  plainToken: string;
}

export async function createUser(params: {
  name: string;
  allowedServices: string[];
  locale: string | null;
}): Promise<CreatedUser> {
  const plainToken = generateToken(32);
  return mutateUsers((draft) => {
    if (draft.users.some((u) => u.name.toLowerCase() === params.name.toLowerCase())) {
      throw new Error("A user with that name already exists");
    }
    const now = new Date().toISOString();
    const c = config();
    const registrationOpenUntil = c.KNOCK_REQUIRE_PASSKEY
      ? new Date(
          Date.now() + c.KNOCK_REGISTRATION_TTL_HOURS * 3_600_000,
        ).toISOString()
      : null;
    const user: UserRecord = {
      id: newUserId(params.name),
      name: params.name,
      tokenHash: sha256Hex(plainToken),
      allowedServices: params.allowedServices,
      locale: params.locale,
      createdAt: now,
      history: [],
      credentials: [],
      registrationOpenUntil,
    };
    draft.users.push(user);
    return { user, plainToken };
  });
}

export async function updateUser(
  id: string,
  patch: { name?: string; allowedServices?: string[]; locale?: string | null },
): Promise<UserRecord> {
  return mutateUsers((draft) => {
    const user = draft.users.find((u) => u.id === id);
    if (!user) throw new Error("User not found");
    if (patch.name !== undefined) user.name = patch.name;
    if (patch.allowedServices !== undefined) user.allowedServices = patch.allowedServices;
    if (patch.locale !== undefined) user.locale = patch.locale;
    return user;
  });
}

export async function deleteUser(id: string): Promise<UserRecord | null> {
  return mutateUsers((draft) => {
    const user = draft.users.find((u) => u.id === id);
    if (!user) return null;
    draft.users = draft.users.filter((u) => u.id !== id);
    return user;
  });
}

export async function rotateToken(id: string): Promise<string> {
  const plainToken = generateToken(32);
  await mutateUsers((draft) => {
    const user = draft.users.find((u) => u.id === id);
    if (!user) throw new Error("User not found");
    user.tokenHash = sha256Hex(plainToken);
  });
  return plainToken;
}

export async function pushHistory(userId: string, entry: UserHistoryEntry): Promise<void> {
  await mutateUsers((draft) => {
    const user = draft.users.find((u) => u.id === userId);
    if (!user) return;
    const kept = user.history.slice(-(HISTORY_MAX - 1));
    kept.push(entry);
    user.history = kept;
  });
}

export async function addKnockCredential(
  userId: string,
  cred: WebAuthnCredential,
): Promise<void> {
  await mutateUsers((draft) => {
    const user = draft.users.find((u) => u.id === userId);
    if (!user) throw new Error("User not found");
    user.credentials.push(cred);
    // Close the registration window after first successful registration.
    user.registrationOpenUntil = null;
  });
}

export async function removeKnockCredential(
  userId: string,
  credentialId: string,
): Promise<void> {
  await mutateUsers((draft) => {
    const user = draft.users.find((u) => u.id === userId);
    if (!user) return;
    user.credentials = user.credentials.filter((c) => c.id !== credentialId);
  });
}

export async function openRegistrationWindow(userId: string): Promise<string> {
  const c = config();
  const until = new Date(
    Date.now() + c.KNOCK_REGISTRATION_TTL_HOURS * 3_600_000,
  ).toISOString();
  await mutateUsers((draft) => {
    const user = draft.users.find((u) => u.id === userId);
    if (!user) throw new Error("User not found");
    user.registrationOpenUntil = until;
  });
  return until;
}

export async function updateCredentialCounter(
  userId: string,
  credentialId: string,
  counter: number,
): Promise<void> {
  await mutateUsers((draft) => {
    const user = draft.users.find((u) => u.id === userId);
    if (!user) return;
    const cred = user.credentials.find((c) => c.id === credentialId);
    if (!cred) return;
    cred.counter = counter;
    cred.lastUsedAt = new Date().toISOString();
  });
}
