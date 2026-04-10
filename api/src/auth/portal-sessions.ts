/**
 * Portal session cookie helpers.
 *
 * When a kid logs in via the portal (discoverable passkey at `/`), they
 * receive a `gd_portal` cookie scoped to `/`. This session is then used
 * by the `/my/*` routes to identify the user without a token URL.
 *
 * Storage reuses the same knock-sessions repo — the KnockSession schema
 * already has userId + idHash + expiry, which is all we need.
 *
 * TTL follows KNOCK_PASSKEY_REAUTH_HOURS (default 30 days), same as the
 * per-token knock session.
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

export const PORTAL_COOKIE_NAME = "gd_portal";

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
  return config().KNOCK_PASSKEY_REAUTH_HOURS * 3_600_000;
}

export async function issuePortalSession(
  res: Response,
  req: Request,
  params: { userId: string },
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
  res.cookie(PORTAL_COOKIE_NAME, plain, cookieOptions(ttlMs()));
  return plain;
}

export async function readAndRefreshPortalSession(
  req: Request,
  res: Response,
): Promise<KnockSession | null> {
  const raw = (req.cookies as Record<string, string | undefined>)?.[PORTAL_COOKIE_NAME];
  if (!raw) return null;
  const idHash = hashKnockSessionId(raw);
  const current = await findKnockSessionByIdHash(idHash);
  if (!current) return null;

  const now = Date.now();
  if (now >= new Date(current.expiresAt).getTime()) {
    await deleteKnockSessionByIdHash(idHash);
    clearPortalCookie(res);
    return null;
  }

  const lastSeenAt = new Date(now).toISOString();
  await mutateKnockSessions((draft) => {
    const s = draft.sessions.find((x) => x.idHash === idHash);
    if (!s) return;
    s.lastSeenAt = lastSeenAt;
  });

  res.cookie(PORTAL_COOKIE_NAME, raw, cookieOptions(ttlMs()));
  return { ...current, lastSeenAt };
}

export function clearPortalCookie(res: Response): void {
  const secure = config().ADMIN_ORIGIN.startsWith("https://");
  res.clearCookie(PORTAL_COOKIE_NAME, {
    httpOnly: true,
    secure,
    sameSite: "strict",
    path: "/",
  });
}

export async function destroyPortalSession(
  req: Request,
  res: Response,
): Promise<void> {
  const raw = (req.cookies as Record<string, string | undefined>)?.[PORTAL_COOKIE_NAME];
  if (raw) {
    await deleteKnockSessionByIdHash(hashKnockSessionId(raw));
  }
  clearPortalCookie(res);
}
