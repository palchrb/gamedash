/**
 * Knock session repository (Phase 3 optional passkey gate).
 *
 * Stored shape mirrors admin-sessions: opaque id hash → session record.
 * A knock session says "this browser already completed the passkey
 * ceremony for user X within the last N hours, so it is allowed to
 * call /u/:token/knock without re-authenticating".
 *
 * The actual cookie is an opaque 256-bit id; we only keep its SHA-256
 * hash on disk, so a stolen knock-sessions.json cannot impersonate a
 * user without the raw cookie.
 *
 * Lifetimes are controlled by KNOCK_PASSKEY_REAUTH_HOURS. The cleanup
 * sweep runs in the background loop alongside admin session sweeping.
 */

import { config } from "../config";
import { readJson, withLock, writeJson } from "../lib/atomic-file";
import { sha256Hex } from "../lib/hash";
import {
  type KnockSession,
  type KnockSessionsFile,
  KnockSessionsFileSchema,
} from "../schemas";

function filePath(): string {
  return config().knockSessionsFile;
}

export async function loadKnockSessions(): Promise<KnockSessionsFile> {
  return readJson(filePath(), KnockSessionsFileSchema, { sessions: [] });
}

export async function saveKnockSessions(data: KnockSessionsFile): Promise<void> {
  await writeJson(filePath(), KnockSessionsFileSchema, data);
}

export async function mutateKnockSessions<T>(
  fn: (draft: KnockSessionsFile) => Promise<T> | T,
): Promise<T> {
  return withLock(`knock-sessions:${filePath()}`, async () => {
    const draft = await loadKnockSessions();
    const result = await fn(draft);
    await saveKnockSessions(draft);
    return result;
  });
}

export async function addKnockSession(session: KnockSession): Promise<void> {
  await mutateKnockSessions((draft) => {
    draft.sessions.push(session);
  });
}

export async function findKnockSessionByIdHash(
  idHash: string,
): Promise<KnockSession | null> {
  const data = await loadKnockSessions();
  return data.sessions.find((s) => s.idHash === idHash) ?? null;
}

export async function deleteKnockSessionByIdHash(idHash: string): Promise<void> {
  await mutateKnockSessions((draft) => {
    draft.sessions = draft.sessions.filter((s) => s.idHash !== idHash);
  });
}

export async function deleteKnockSessionsForUser(userId: string): Promise<number> {
  let removed = 0;
  await mutateKnockSessions((draft) => {
    const before = draft.sessions.length;
    draft.sessions = draft.sessions.filter((s) => s.userId !== userId);
    removed = before - draft.sessions.length;
  });
  return removed;
}

export async function sweepExpiredKnockSessions(): Promise<number> {
  let removed = 0;
  const now = Date.now();
  await mutateKnockSessions((draft) => {
    const before = draft.sessions.length;
    draft.sessions = draft.sessions.filter(
      (s) => new Date(s.expiresAt).getTime() > now,
    );
    removed = before - draft.sessions.length;
  });
  return removed;
}

export function hashKnockSessionId(plain: string): string {
  return sha256Hex(plain);
}
