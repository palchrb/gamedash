/**
 * Admin session lifecycle + cookie helpers.
 *
 * Sessions are opaque 256-bit random ids stored in an HttpOnly, Secure,
 * SameSite=Strict cookie. The server keeps only their SHA-256 hash on
 * disk, so a stolen admin-sessions.json is not enough to impersonate an
 * admin — an attacker would also need the raw cookie.
 *
 * Two timestamps gate each session:
 *   expiresAt     hard cut-off (default 12 h). Past this point the
 *                 session is gone, period. Set by ADMIN_SESSION_TTL_HOURS.
 *   reauthAfter   glide deadline (default 168 h). If a session's
 *                 lastSeenAt is newer than this timestamp each hit we
 *                 extend expiresAt to now+TTL. If lastSeenAt drifts past
 *                 it, the session refuses to renew and the user has to
 *                 redo the passkey ceremony. Set by ADMIN_REAUTH_AFTER_HOURS.
 *
 * The combination gives a forgiving "mostly online daily" UX while
 * guaranteeing a hard re-auth boundary.
 */

import type { CookieOptions, Request, Response } from "express";
import { config } from "../config";
import { generateSessionId } from "../lib/hash";
import {
  addAdminSession,
  deleteAdminSessionByIdHash,
  findAdminSessionByIdHash,
  hashSessionId,
  mutateAdminSessions,
} from "../repos/admin";
import type { AdminSession } from "../schemas";

export const ADMIN_COOKIE_NAME = "gd_admin";

function cookieOptions(maxAgeMs: number): CookieOptions {
  const secure = config().ADMIN_ORIGIN.startsWith("https://");
  return {
    httpOnly: true,
    secure,
    sameSite: "strict",
    path: "/",
    maxAge: maxAgeMs,
  };
}

function ttlMs(): number {
  return config().ADMIN_SESSION_TTL_HOURS * 3_600_000;
}

function reauthMs(): number {
  return config().ADMIN_REAUTH_AFTER_HOURS * 3_600_000;
}

/**
 * Create a brand-new admin session, persist it, and set the cookie on
 * the response. Returns the plaintext session id for logging tests.
 */
export async function issueAdminSession(
  res: Response,
  req: Request,
  adminId: string,
): Promise<string> {
  const plain = generateSessionId(32);
  const idHash = hashSessionId(plain);
  const now = new Date();
  const session: AdminSession = {
    idHash,
    adminId,
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + ttlMs()).toISOString(),
    reauthAfter: new Date(now.getTime() + reauthMs()).toISOString(),
    lastSeenAt: now.toISOString(),
    ip: (req.ip ?? "").toString(),
    ua: req.headers["user-agent"] ?? null,
  };
  await addAdminSession(session);
  res.cookie(ADMIN_COOKIE_NAME, plain, cookieOptions(ttlMs()));
  return plain;
}

/**
 * Look up the session belonging to the cookie on this request and, if
 * it is still within both limits, refresh lastSeenAt + expiresAt in
 * place. Returns null for missing/expired/past-reauth.
 */
export async function readAndRefreshAdminSession(
  req: Request,
  res: Response,
): Promise<AdminSession | null> {
  const raw = (req.cookies as Record<string, string | undefined>)?.[ADMIN_COOKIE_NAME];
  if (!raw) return null;
  const idHash = hashSessionId(raw);
  const current = await findAdminSessionByIdHash(idHash);
  if (!current) return null;

  const now = Date.now();
  const expiresAtMs = new Date(current.expiresAt).getTime();
  const reauthAfterMs = new Date(current.reauthAfter).getTime();

  if (now >= expiresAtMs) {
    await deleteAdminSessionByIdHash(idHash);
    clearAdminCookie(res);
    return null;
  }
  if (now >= reauthAfterMs) {
    // Glide re-auth deadline hit. Blow the session away so the next
    // request forces the UI back to the login screen.
    await deleteAdminSessionByIdHash(idHash);
    clearAdminCookie(res);
    return null;
  }

  // Slide the expiry forward. This is what turns the hard 12 h TTL into
  // "the session lives as long as you come back within 12 h".
  const newExpiresAt = new Date(now + ttlMs()).toISOString();
  const lastSeenAt = new Date(now).toISOString();
  await mutateAdminSessions((draft) => {
    const s = draft.sessions.find((x) => x.idHash === idHash);
    if (!s) return;
    s.expiresAt = newExpiresAt;
    s.lastSeenAt = lastSeenAt;
  });

  res.cookie(ADMIN_COOKIE_NAME, raw, cookieOptions(ttlMs()));
  return { ...current, expiresAt: newExpiresAt, lastSeenAt };
}

export function clearAdminCookie(res: Response): void {
  const secure = config().ADMIN_ORIGIN.startsWith("https://");
  res.clearCookie(ADMIN_COOKIE_NAME, {
    httpOnly: true,
    secure,
    sameSite: "strict",
    path: "/",
  });
}

export async function destroyAdminSession(req: Request, res: Response): Promise<void> {
  const raw = (req.cookies as Record<string, string | undefined>)?.[ADMIN_COOKIE_NAME];
  if (raw) {
    await deleteAdminSessionByIdHash(hashSessionId(raw));
  }
  clearAdminCookie(res);
}
