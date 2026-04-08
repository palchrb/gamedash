/**
 * Knock-session cookie helpers (Phase 3).
 *
 * When `KNOCK_REQUIRE_PASSKEY=true`, each knock-PWA user must complete a
 * WebAuthn ceremony and receive a cookie-backed session before the
 * `/u/:token/knock` endpoint is willing to do anything. This file owns
 * the cookie format and the read/issue/destroy helpers.
 *
 * Cookie scope: path is restricted to `/u/<token>/` so every child gets
 * their own cookie and one child's session does not leak into another
 * child's PWA even if they share a browser profile. SameSite is strict
 * for the same reason it is on the admin cookie: knock is a sensitive
 * write endpoint and we never want it to fire from a cross-site context.
 *
 * TTL: governed by KNOCK_PASSKEY_REAUTH_HOURS (default 30 days). The
 * knock PWA is meant to be installed once and used without further
 * friction; a month is the usual sweet spot.
 */

import type { CookieOptions, Request, Response } from "express";
import { config } from "../config";
import { generateSessionId } from "../lib/hash";
import {
  addKnockSession,
  deleteKnockSessionByIdHash,
  findKnockSessionByIdHash,
  hashKnockSessionId,
  mutateKnockSessions,
} from "../repos/knock-sessions";
import type { KnockSession } from "../schemas";

export const KNOCK_COOKIE_NAME = "gd_knock";

function cookiePath(token: string): string {
  return `/u/${token}/`;
}

function cookieOptions(token: string, maxAgeMs: number): CookieOptions {
  const secure = config().ADMIN_ORIGIN.startsWith("https://");
  return {
    httpOnly: true,
    secure,
    sameSite: "strict",
    path: cookiePath(token),
    maxAge: maxAgeMs,
  };
}

function ttlMs(): number {
  return config().KNOCK_PASSKEY_REAUTH_HOURS * 3_600_000;
}

/**
 * Create a brand-new knock session, persist it, and set the cookie on
 * the response.
 */
export async function issueKnockSession(
  res: Response,
  req: Request,
  params: { userId: string; token: string },
): Promise<string> {
  const plain = generateSessionId(32);
  const idHash = hashKnockSessionId(plain);
  const now = new Date();
  const session: KnockSession = {
    idHash,
    userId: params.userId,
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + ttlMs()).toISOString(),
    lastSeenAt: now.toISOString(),
    ip: (req.ip ?? "").toString(),
    ua: req.headers["user-agent"] ?? null,
  };
  await addKnockSession(session);
  res.cookie(KNOCK_COOKIE_NAME, plain, cookieOptions(params.token, ttlMs()));
  return plain;
}

/**
 * Read the knock session for this request, enforce expiry, and slide
 * lastSeenAt forward. Returns null for missing / expired / mismatched
 * user sessions. The caller is responsible for matching the returned
 * session's userId against the user derived from the URL token.
 */
export async function readAndRefreshKnockSession(
  req: Request,
  res: Response,
  token: string,
): Promise<KnockSession | null> {
  const raw = (req.cookies as Record<string, string | undefined>)?.[KNOCK_COOKIE_NAME];
  if (!raw) return null;
  const idHash = hashKnockSessionId(raw);
  const current = await findKnockSessionByIdHash(idHash);
  if (!current) return null;

  const now = Date.now();
  if (now >= new Date(current.expiresAt).getTime()) {
    await deleteKnockSessionByIdHash(idHash);
    clearKnockCookie(res, token);
    return null;
  }

  const lastSeenAt = new Date(now).toISOString();
  await mutateKnockSessions((draft) => {
    const s = draft.sessions.find((x) => x.idHash === idHash);
    if (!s) return;
    s.lastSeenAt = lastSeenAt;
  });

  // Refresh cookie maxAge so the session is "sticky while actively used".
  res.cookie(KNOCK_COOKIE_NAME, raw, cookieOptions(token, ttlMs()));
  return { ...current, lastSeenAt };
}

export function clearKnockCookie(res: Response, token: string): void {
  const secure = config().ADMIN_ORIGIN.startsWith("https://");
  res.clearCookie(KNOCK_COOKIE_NAME, {
    httpOnly: true,
    secure,
    sameSite: "strict",
    path: cookiePath(token),
  });
}

export async function destroyKnockSession(
  req: Request,
  res: Response,
  token: string,
): Promise<void> {
  const raw = (req.cookies as Record<string, string | undefined>)?.[KNOCK_COOKIE_NAME];
  if (raw) {
    await deleteKnockSessionByIdHash(hashKnockSessionId(raw));
  }
  clearKnockCookie(res, token);
}
