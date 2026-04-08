/**
 * Admin gate for the API.
 *
 * `requireAdmin` reads the session cookie, refreshes the session's
 * lastSeenAt + expiresAt, and attaches the admin id to the request as
 * `req.adminId`. Missing or expired sessions get a 401.
 *
 * The gate is applied in `app.ts` only to /api/* routes that are not
 * in the public allow-list (i18n bootstrap, login/logout, healthz, the
 * per-user knock PWA on /u/* which has its own token auth).
 */

import type { NextFunction, Request, Response } from "express";
import { readAndRefreshAdminSession } from "./sessions";

declare module "express-serve-static-core" {
  interface Request {
    adminId?: string;
  }
}

export async function requireAdmin(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  try {
    const session = await readAndRefreshAdminSession(req, res);
    if (!session) {
      res.status(401).json({ success: false, error: "admin login required" });
      return;
    }
    req.adminId = session.adminId;
    next();
  } catch (err) {
    next(err);
  }
}
