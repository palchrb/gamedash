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
import {
  sha256Hex,
  generateToken,
  generateShareCode,
  constantTimeEqualHex,
} from "../lib/hash";
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

/**
 * Publicly safe user projection — never includes plaintext tokens.
 * Token entries expose only their sha-256 hash (used as a revocation
 * handle by the admin UI; the hash cannot be turned back into a link).
 */
export interface PublicUser {
  id: string;
  name: string;
  allowedServices: string[];
  locale: string | null;
  createdAt: string;
  hasCredentials: boolean;
  registrationOpenUntil: string | null;
  suspended: boolean;
  credentials: Array<{
    id: string;
    deviceLabel: string | null;
    createdAt: string;
    lastUsedAt: string | null;
  }>;
  tokens: Array<{
    hash: string;
    createdAt: string;
    label: string | null;
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
    suspended: u.suspended ?? false,
    credentials: u.credentials.map((c) => ({
      id: c.id,
      deviceLabel: c.deviceLabel ?? null,
      createdAt: c.createdAt,
      lastUsedAt: c.lastUsedAt,
    })),
    tokens: u.tokens.map((t) => ({
      hash: t.hash,
      createdAt: t.createdAt,
      label: t.label ?? null,
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
    for (const t of u.tokens) {
      if (constantTimeEqualHex(t.hash, candidateHash)) return u;
    }
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
      tokens: [{ hash: sha256Hex(plainToken), createdAt: now, label: null }],
      claimCode: null,
      allowedServices: params.allowedServices,
      locale: params.locale,
      createdAt: now,
      history: [],
      credentials: [],
      registrationOpenUntil,
      suspended: false,
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

/**
 * Rotate: kill EVERY token (all devices) and any outstanding claim code,
 * replace with a single fresh token. This is the "assume the link leaked"
 * panic button — the semantics predate multi-token support on purpose.
 */
export async function rotateToken(id: string): Promise<string> {
  const plainToken = generateToken(32);
  await mutateUsers((draft) => {
    const user = draft.users.find((u) => u.id === id);
    if (!user) throw new Error("User not found");
    user.tokens = [
      { hash: sha256Hex(plainToken), createdAt: new Date().toISOString(), label: null },
    ];
    user.claimCode = null;
  });
  return plainToken;
}

// ── Share codes (admin-minted, single-use, short TTL) ─────────────────

export const CLAIM_CODE_TTL_MS = 10 * 60 * 1000;
const MAX_TOKENS_PER_USER = 10;

/**
 * Mint a share code for a user. Overwrites any previous outstanding code
 * (one live code per user). Returns the plaintext code exactly once.
 * Refuses suspended users — they must not gain new entry points.
 */
export async function mintClaimCode(
  userId: string,
): Promise<{ code: string; expiresAt: string }> {
  const code = generateShareCode();
  const expiresAt = new Date(Date.now() + CLAIM_CODE_TTL_MS).toISOString();
  await mutateUsers((draft) => {
    const user = draft.users.find((u) => u.id === userId);
    if (!user) throw new Error("User not found");
    if (user.suspended) throw new Error("User is suspended");
    user.claimCode = { codeHash: sha256Hex(code), expiresAt };
  });
  return { code, expiresAt };
}

/** True if any user currently has an unexpired claim code outstanding. */
export async function anyClaimCodeOutstanding(): Promise<boolean> {
  const data = await loadUsers();
  const now = Date.now();
  return data.users.some(
    (u) => u.claimCode && new Date(u.claimCode.expiresAt).getTime() > now,
  );
}

/**
 * Redeem a share code: consume it atomically and mint a fresh token for
 * the matching user. Returns null when the code matches nothing (wrong,
 * expired, or already used) — the caller treats all three identically so
 * responses don't leak which case occurred.
 */
export async function claimShareCode(
  normalizedCode: string,
): Promise<{ user: UserRecord; plainToken: string } | null> {
  const codeHash = sha256Hex(normalizedCode);
  const plainToken = generateToken(32);
  const now = Date.now();
  return mutateUsers((draft) => {
    for (const user of draft.users) {
      if (!user.claimCode) continue;
      if (!constantTimeEqualHex(user.claimCode.codeHash, codeHash)) continue;
      const expired = new Date(user.claimCode.expiresAt).getTime() <= now;
      // Consume on any match, valid or expired — a matched-but-expired
      // code must not stay guessable forever.
      user.claimCode = null;
      if (expired || user.suspended) return null;
      user.tokens.push({
        hash: sha256Hex(plainToken),
        createdAt: new Date().toISOString(),
        label: "via share code",
      });
      // Bound the token list so repeated claims can't grow it forever;
      // drop the oldest non-original tokens first.
      while (user.tokens.length > MAX_TOKENS_PER_USER) {
        user.tokens.splice(1, 1);
      }
      return { user, plainToken };
    }
    return null;
  });
}

/** Look up the user (if any) holding a live claim code — for the claim page's name display. */
export async function findUserByClaimCode(
  normalizedCode: string,
): Promise<UserRecord | null> {
  const codeHash = sha256Hex(normalizedCode);
  const data = await loadUsers();
  const now = Date.now();
  for (const user of data.users) {
    if (!user.claimCode) continue;
    if (!constantTimeEqualHex(user.claimCode.codeHash, codeHash)) continue;
    if (new Date(user.claimCode.expiresAt).getTime() <= now) return null;
    if (user.suspended) return null;
    return user;
  }
  return null;
}

/** Revoke a single device token by its hash. Refuses to remove the last one. */
export async function revokeUserToken(
  userId: string,
  tokenHash: string,
): Promise<boolean> {
  return mutateUsers((draft) => {
    const user = draft.users.find((u) => u.id === userId);
    if (!user) throw new Error("User not found");
    if (user.tokens.length <= 1) throw new Error("Cannot remove the last token");
    const before = user.tokens.length;
    user.tokens = user.tokens.filter((t) => t.hash !== tokenHash);
    return user.tokens.length < before;
  });
}

export async function suspendUser(id: string): Promise<UserRecord> {
  return mutateUsers((draft) => {
    const user = draft.users.find((u) => u.id === id);
    if (!user) throw new Error("User not found");
    user.suspended = true;
    return user;
  });
}

export async function reinstateUser(id: string): Promise<UserRecord> {
  return mutateUsers((draft) => {
    const user = draft.users.find((u) => u.id === id);
    if (!user) throw new Error("User not found");
    user.suspended = false;
    return user;
  });
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
