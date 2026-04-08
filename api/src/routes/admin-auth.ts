/**
 * Admin auth endpoints — passkey enroll + sign-in + session introspection.
 *
 * Routes (all under /api/admin):
 *   GET  /me                              current session (or 401)
 *   GET  /bootstrap                       {open, expiresAt, minutesRemaining}
 *   POST /bootstrap/start                 creates the first admin record
 *   POST /webauthn/register/options       options for navigator.credentials.create
 *   POST /webauthn/register/verify        persists the new credential
 *   POST /webauthn/authenticate/options   options for navigator.credentials.get
 *   POST /webauthn/authenticate/verify    issues a session cookie on success
 *   POST /logout                          destroys the current session
 *
 * The routes that create state (register, verify, logout) are rate-limited
 * separately from the rest of the API to slow down any brute-force attempt
 * on the public-facing endpoints.
 */

import { Router } from "express";
import rateLimit from "express-rate-limit";
import { z } from "zod";
import { audit } from "../repos/audit";
import {
  createAdmin,
  findAdminById,
  hasAnyAdmin,
  loadAdminCredentials,
} from "../repos/admin";
import { asyncH } from "../middleware/async-handler";
import { HttpError } from "../middleware/error-handler";
import {
  generateAuthenticationOpts,
  generateRegistrationOpts,
  verifyAuthentication,
  verifyRegistration,
} from "../auth/admin-passkey";
import {
  bootstrapStatus,
  closeBootstrap,
  isBootstrapOpen,
} from "../auth/bootstrap";
import {
  destroyAdminSession,
  issueAdminSession,
  readAndRefreshAdminSession,
} from "../auth/sessions";
import { adminLogins, authFailures, incCounter } from "../metrics";

const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: "too many auth requests" },
});

const BootstrapBodySchema = z.object({
  name: z.string().min(1).max(64),
});

const RegisterOptionsBodySchema = z.object({
  adminId: z.string().min(1),
});

const RegisterVerifyBodySchema = z.object({
  adminId: z.string().min(1),
  deviceLabel: z.string().max(64).optional(),
  response: z.unknown(),
});

const AuthenticateVerifyBodySchema = z.object({
  response: z.unknown(),
});

// The authentication options route is un-authenticated; we use a fixed
// key so there can only ever be one pending ceremony per server process.
// This is fine because a challenge is single-use anyway.
const AUTH_CHALLENGE_KEY = "auth:current";

export function adminAuthRouter(): Router {
  const router = Router();

  router.use("/api/admin", authLimiter);

  // ── session introspection ────────────────────────────────────────────
  router.get(
    "/api/admin/me",
    asyncH(async (req, res) => {
      const session = await readAndRefreshAdminSession(req, res);
      if (!session) {
        res.status(401).json({ success: false, error: "not authenticated" });
        return;
      }
      const admin = await findAdminById(session.adminId);
      res.json({
        success: true,
        admin: admin ? { id: admin.id, name: admin.name } : null,
        session: {
          expiresAt: session.expiresAt,
          reauthAfter: session.reauthAfter,
          lastSeenAt: session.lastSeenAt,
        },
      });
    }),
  );

  // ── bootstrap window ─────────────────────────────────────────────────
  router.get("/api/admin/bootstrap", (_req, res) => {
    res.json({ success: true, ...bootstrapStatus() });
  });

  router.post(
    "/api/admin/bootstrap/start",
    asyncH(async (req, res) => {
      if (!isBootstrapOpen()) {
        throw new HttpError(
          403,
          "bootstrap window closed — restart the server to re-open it",
        );
      }
      if (await hasAnyAdmin()) {
        throw new HttpError(403, "an admin already exists");
      }
      const body = BootstrapBodySchema.parse(req.body);
      const admin = await createAdmin(body.name);
      // Note: we do NOT close the bootstrap window here. The register
      // ceremony has to complete first, or a user who fails half-way
      // through would be permanently locked out.
      await audit({ kind: "admin.bootstrap_start", adminId: admin.id, name: admin.name });
      res.json({ success: true, adminId: admin.id, name: admin.name });
    }),
  );

  // ── registration ─────────────────────────────────────────────────────
  router.post(
    "/api/admin/webauthn/register/options",
    asyncH(async (req, res) => {
      const body = RegisterOptionsBodySchema.parse(req.body);

      // Allow adding new credentials in two distinct contexts:
      //   1. During the bootstrap window, for the admin just created
      //      by /bootstrap/start (no session yet).
      //   2. For an authenticated admin adding an extra device, once
      //      the system is up and running.
      const session = await readAndRefreshAdminSession(req, res);
      if (!session && !isBootstrapOpen()) {
        throw new HttpError(401, "login required");
      }
      if (session && session.adminId !== body.adminId) {
        throw new HttpError(403, "cannot register credential for another admin");
      }

      const admin = await findAdminById(body.adminId);
      if (!admin) throw new HttpError(404, "admin not found");
      const options = await generateRegistrationOpts(admin);
      res.json({ success: true, options });
    }),
  );

  router.post(
    "/api/admin/webauthn/register/verify",
    asyncH(async (req, res) => {
      const body = RegisterVerifyBodySchema.parse(req.body);

      const session = await readAndRefreshAdminSession(req, res);
      const existingAdmins = await loadAdminCredentials();
      const target = existingAdmins.admins.find((a) => a.id === body.adminId);
      if (!target) throw new HttpError(404, "admin not found");

      const isFirstCredential = target.credentials.length === 0;
      if (!session) {
        // Unauthenticated path is only valid during the bootstrap window
        // and only for finishing the very first credential of the first
        // admin.
        if (!isBootstrapOpen() || !isFirstCredential) {
          throw new HttpError(401, "login required");
        }
      } else if (session.adminId !== body.adminId) {
        throw new HttpError(403, "cannot register credential for another admin");
      }

      try {
        await verifyRegistration({
          adminId: body.adminId,
          response: body.response,
          deviceLabel: body.deviceLabel,
        });
      } catch (err) {
        throw new HttpError(400, (err as Error).message);
      }

      if (isFirstCredential) {
        // First credential is stored → bootstrap window's job is done.
        closeBootstrap();
        await audit({ kind: "admin.bootstrap_complete", adminId: body.adminId });
        // Log them in automatically so they don't have to immediately
        // redo the passkey ceremony right after registering it.
        await issueAdminSession(res, req, body.adminId);
      } else {
        await audit({
          kind: "admin.credential_added",
          adminId: body.adminId,
          deviceLabel: body.deviceLabel ?? null,
        });
      }
      res.json({ success: true });
    }),
  );

  // ── authentication ───────────────────────────────────────────────────
  router.post(
    "/api/admin/webauthn/authenticate/options",
    asyncH(async (_req, res) => {
      const options = await generateAuthenticationOpts(AUTH_CHALLENGE_KEY);
      res.json({ success: true, options });
    }),
  );

  router.post(
    "/api/admin/webauthn/authenticate/verify",
    asyncH(async (req, res) => {
      const body = AuthenticateVerifyBodySchema.parse(req.body);
      let result;
      try {
        result = await verifyAuthentication({
          challengeKey: AUTH_CHALLENGE_KEY,
          response: body.response,
        });
      } catch (err) {
        incCounter(authFailures, { kind: "admin" });
        throw new HttpError(401, (err as Error).message);
      }
      await issueAdminSession(res, req, result.adminId);
      await audit({ kind: "admin.login", adminId: result.adminId });
      incCounter(adminLogins);
      const admin = await findAdminById(result.adminId);
      res.json({
        success: true,
        admin: admin ? { id: admin.id, name: admin.name } : null,
      });
    }),
  );

  // ── logout ───────────────────────────────────────────────────────────
  router.post(
    "/api/admin/logout",
    asyncH(async (req, res) => {
      const session = await readAndRefreshAdminSession(req, res);
      await destroyAdminSession(req, res);
      if (session) {
        await audit({ kind: "admin.logout", adminId: session.adminId });
      }
      res.json({ success: true });
    }),
  );

  return router;
}
