/**
 * Kids portal routes.
 *
 * When KNOCK_REQUIRE_PASSKEY=true, the root URL (`/`) serves a kids
 * portal where children sign in with their passkey (discoverable
 * credentials) and land on `/my` — a cookie-authenticated version of
 * the knock PWA that doesn't need a token URL.
 *
 * When KNOCK_REQUIRE_PASSKEY=false, `GET /` redirects to `/admin`.
 *
 * Existing `/u/:token` URLs keep working unchanged.
 *
 * Routes:
 *   GET  /                                    landing page or redirect
 *   POST /portal/webauthn/authenticate/options discoverable auth challenge
 *   POST /portal/webauthn/authenticate/verify  verify passkey → session
 *   POST /portal/logout                        destroy portal session
 *   GET  /my                                   knock PWA (session-auth)
 *   GET  /my/state                             current rule + services
 *   POST /my/knock                             knock entry point
 *   POST /my/revoke                            revoke firewall rule
 *   GET  /my/stats                             playtime stats
 *   GET  /my/manifest.json                     PWA manifest
 *   GET  /my/sw.js, u.js, u.css, webauthn.js  static PWA assets
 */

import * as path from "node:path";
import { Router } from "express";
import rateLimit from "express-rate-limit";
import { z } from "zod";
import type { Request, Response, NextFunction } from "express";
import { asyncH } from "../middleware/async-handler";
import { HttpError } from "../middleware/error-handler";
import { clientIp, isInIgnoredRange } from "../lib/ip";
import { getDictForClient, resolveLang } from "../lib/i18n";
import { knockUser, revokeUser } from "../knock/smart-revoke";
import { findById } from "../repos/users";
import { findRuleByUserId } from "../repos/firewall-rules";
import { summarizeUser } from "../repos/stats";
import { registry } from "../services/registry";
import { config } from "../config";
import {
  generatePortalAuthenticationOpts,
  verifyPortalAuthentication,
} from "../auth/portal-passkey";
import {
  destroyPortalSession,
  issuePortalSession,
  readAndRefreshPortalSession,
} from "../auth/portal-sessions";
import { renderUserPwa } from "./knock-pwa";
import { audit } from "../repos/audit";
import { authFailures, incCounter, knockAttempts, knockLogins } from "../metrics";
import type { UserRecord } from "../schemas";

const PWA_DIR = path.resolve(__dirname, "..", "..", "pwa");
const WEBAUTHN_JS = path.resolve(__dirname, "..", "..", "public", "webauthn.js");

const portalAuthLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: "too many auth requests" },
});

const knockLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: "too many requests" },
});

const AuthenticateVerifyBodySchema = z.object({
  response: z.unknown(),
});

/**
 * Middleware: require a valid portal session. Populates req.portalUser.
 */
async function requirePortalSession(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const session = await readAndRefreshPortalSession(req, res);
  if (!session) {
    res.status(401).json({ success: false, error: "portal login required" });
    return;
  }
  const user = await findById(session.userId);
  if (!user) {
    res.status(401).json({ success: false, error: "user not found" });
    return;
  }
  (req as Request & { portalUser: UserRecord }).portalUser = user;
  next();
}

function getPortalUser(req: Request): UserRecord {
  return (req as Request & { portalUser: UserRecord }).portalUser;
}

function buildServiceList(user: UserRecord) {
  return user.allowedServices.map((id) => {
    const a = registry().get(id);
    return a
      ? {
          id,
          name: a.name,
          ports: a.ports,
          ...(a.mapUrl ? { mapUrl: a.mapUrl } : {}),
          ...(a.connectAddress ? { connectAddress: a.connectAddress } : {}),
        }
      : { id, name: id };
  });
}

export function portalRouter(): Router {
  const router = Router();

  // ── Landing page ──────────────────────────────────────────────────────
  router.get(
    "/",
    asyncH(async (req, res) => {
      if (!config().KNOCK_REQUIRE_PASSKEY) {
        res.redirect("/admin");
        return;
      }
      // If already logged in, redirect to /my
      const session = await readAndRefreshPortalSession(req, res);
      if (session) {
        const user = await findById(session.userId);
        if (user) {
          res.redirect("/my");
          return;
        }
      }
      // Render a simple login page using the PWA template
      const lang = resolveLang(req);
      const dict = getDictForClient(lang);
      const initial = {
        portalMode: true,
        portalLogin: true,
        lang,
        requirePasskey: true,
        hasCredentials: true,
        registrationOpen: false,
      };
      res
        .type("html")
        .send(renderUserPwa({ initial, dict, lang, base: "/my" }));
    }),
  );

  // ── Portal WebAuthn ───────────────────────────────────────────────────

  router.post(
    "/portal/webauthn/authenticate/options",
    portalAuthLimiter,
    asyncH(async (_req, res) => {
      const options = await generatePortalAuthenticationOpts();
      res.json({ success: true, options });
    }),
  );

  router.post(
    "/portal/webauthn/authenticate/verify",
    portalAuthLimiter,
    asyncH(async (req, res) => {
      const body = AuthenticateVerifyBodySchema.parse(req.body);
      let result;
      try {
        result = await verifyPortalAuthentication({ response: body.response });
      } catch (err) {
        incCounter(authFailures, { kind: "portal" });
        throw new HttpError(401, (err as Error).message);
      }
      await issuePortalSession(res, req, { userId: result.userId });
      await audit({ kind: "portal.login", userId: result.userId });
      incCounter(knockLogins);
      res.json({ success: true, redirect: "/my" });
    }),
  );

  router.post(
    "/portal/logout",
    asyncH(async (req, res) => {
      await destroyPortalSession(req, res);
      res.json({ success: true });
    }),
  );

  // ── /my — authenticated knock PWA ────────────────────────────────────

  router.get(
    "/my",
    asyncH(async (req, res) => {
      const session = await readAndRefreshPortalSession(req, res);
      if (!session) {
        res.redirect("/");
        return;
      }
      const user = await findById(session.userId);
      if (!user) {
        res.redirect("/");
        return;
      }
      const lang = resolveLang(req, user);
      const dict = getDictForClient(lang);
      const services = buildServiceList(user);
      const initial = {
        portalMode: true,
        user: { id: user.id, name: user.name },
        services,
        lang,
        requirePasskey: true,
        hasCredentials: user.credentials.length > 0,
        registrationOpen: false,
      };
      res
        .type("html")
        .send(renderUserPwa({ initial, dict, lang, base: "/my" }));
    }),
  );

  router.get(
    "/my/state",
    requirePortalSession,
    asyncH(async (req, res) => {
      const user = getPortalUser(req);
      const rule = await findRuleByUserId(user.id);
      const services = buildServiceList(user);

      res.json({
        success: true,
        user: { id: user.id, name: user.name },
        services,
        active: rule
          ? {
              ip: rule.ip,
              expiresAt: rule.expiresAt ?? null,
              services: rule.services.map((s) => s.id),
            }
          : null,
        auth: {
          requirePasskey: true,
          hasCredentials: user.credentials.length > 0,
          registrationOpen: false,
          sessionValid: true,
        },
      });
    }),
  );

  router.post(
    "/my/knock",
    knockLimiter,
    requirePortalSession,
    asyncH(async (req, res) => {
      const user = getPortalUser(req);
      incCounter(knockAttempts);

      const ip = clientIp(req);
      const force = req.query["force"] === "true" || (req.body as { force?: boolean })?.force === true;
      const bodyServices = (req.body as { services?: unknown })?.services;
      const querySvcs = req.query["services"];
      const raw = bodyServices ?? querySvcs ?? "all";
      let requested: string[] | "all";
      if (raw === "all") requested = "all";
      else if (Array.isArray(raw)) requested = raw.map(String);
      else if (typeof raw === "string")
        requested = raw.split(",").map((s) => s.trim()).filter(Boolean);
      else requested = "all";

      if (isInIgnoredRange(ip, config())) {
        res.json({
          success: true,
          ip,
          ignored: true,
          expiresAt: null,
          services: [],
        });
        return;
      }

      const result = await knockUser(user, ip, requested, registry(), {
        force,
        ua: req.headers["user-agent"] ?? null,
      });
      if (result.status === "requires_confirm") {
        res.status(409).json({
          success: false,
          requireConfirm: result.reason,
          oldIp: result.oldIp,
          matchCount: result.matchCount,
          oldServices: result.oldServices,
        });
        return;
      }
      res.json({
        success: true,
        ip,
        expiresAt: result.expiresAt,
        services: result.rule.services.map((s) => s.id),
      });
    }),
  );

  router.post(
    "/my/revoke",
    requirePortalSession,
    asyncH(async (req, res) => {
      const user = getPortalUser(req);
      const r = await revokeUser(user.id);
      res.json({ success: true, ...r });
    }),
  );

  router.get(
    "/my/stats",
    requirePortalSession,
    asyncH(async (req, res) => {
      const user = getPortalUser(req);
      res.json({ success: true, stats: await summarizeUser(user.id) });
    }),
  );

  // ── /my PWA assets ────────────────────────────────────────────────────

  router.get("/my/manifest.json", (_req, res) => {
    res.json({
      name: "Game Knock",
      short_name: "Play",
      start_url: "/my",
      scope: "/my",
      display: "standalone",
      background_color: "#1a1a2e",
      theme_color: "#1a1a2e",
      icons: [
        {
          src: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 192 192'%3E%3Crect fill='%232d6a4f' width='192' height='192' rx='28'/%3E%3Ctext x='96' y='128' text-anchor='middle' font-size='96' font-family='sans-serif' fill='white'%3E%E2%9C%93%3C/text%3E%3C/svg%3E",
          sizes: "192x192 512x512",
          type: "image/svg+xml",
          purpose: "any maskable",
        },
      ],
    });
  });

  router.get("/my/sw.js", (_req, res) => {
    res.type("application/javascript").sendFile(path.join(PWA_DIR, "sw.js"));
  });
  router.get("/my/u.js", (_req, res) => {
    res.type("application/javascript").sendFile(path.join(PWA_DIR, "u.js"));
  });
  router.get("/my/u.css", (_req, res) => {
    res.type("text/css").sendFile(path.join(PWA_DIR, "u.css"));
  });
  router.get("/my/webauthn.js", (_req, res) => {
    res.type("application/javascript").sendFile(WEBAUTHN_JS);
  });

  return router;
}
