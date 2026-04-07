/**
 * Per-user knock PWA routes.
 *
 * /u/:token                 → server-rendered PWA HTML (inlined i18n + init)
 * /u/:token/state           → current active rule, allowed services
 * /u/:token/knock           → auto-knock entry point with smart-revoke
 * /u/:token/revoke          → user-initiated revoke
 * /u/:token/stats           → user's own playtime summary
 * /u/:token/manifest.json   → per-user PWA manifest (scoped to token)
 * /u/:token/sw.js           → service worker (static, cached)
 * /u/:token/u.js            → PWA client script (static, cached)
 * /u/:token/u.css           → PWA stylesheet (static, cached)
 *
 * Token in URL is the only form of auth in Phase 0. Tokens are 256-bit,
 * stored as SHA-256 hash, compared in constant time via findByToken.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { Router } from "express";
import rateLimit from "express-rate-limit";
import { asyncH } from "../middleware/async-handler";
import { HttpError } from "../middleware/error-handler";
import { clientIp, isInIgnoredRange } from "../lib/ip";
import { getDictForClient, resolveLang } from "../lib/i18n";
import { knockUser, revokeUser } from "../knock/smart-revoke";
import { findByToken } from "../repos/users";
import { findRuleByUserId } from "../repos/firewall-rules";
import { summarizeUser } from "../repos/stats";
import { registry } from "../services/registry";
import { config } from "../config";
import type { UserRecord } from "../schemas";

const PWA_DIR = path.resolve(__dirname, "..", "..", "pwa");

const knockLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: "too many requests" },
});

async function userFromToken(token: string | undefined): Promise<UserRecord> {
  if (!token) throw new HttpError(404, "invalid token");
  const user = await findByToken(token);
  if (!user) throw new HttpError(404, "invalid token");
  return user;
}

let cachedPwaTemplate: string | null = null;
function renderUserPwa(params: {
  initial: Record<string, unknown>;
  dict: Record<string, string>;
  lang: string;
  token: string;
}): string {
  if (!cachedPwaTemplate) {
    try {
      cachedPwaTemplate = fs.readFileSync(path.join(PWA_DIR, "index.html"), "utf8");
    } catch {
      cachedPwaTemplate = "<!doctype html><h1>PWA template missing</h1>";
    }
  }
  const base = `/u/${params.token}`;
  const initBlob = `<script>window.__I18N__=${JSON.stringify(params.dict)};window.__INIT__=${JSON.stringify(params.initial)};</script>`;
  return cachedPwaTemplate
    .replace(/\{\{LANG\}\}/gu, params.lang)
    .replace(/\{\{BASE\}\}/gu, base)
    .replace(/\{\{INIT\}\}/gu, initBlob);
}

export function knockPwaRouter(): Router {
  const router = Router();

  router.get(
    "/u/:token",
    asyncH(async (req, res) => {
      const user = await findByToken(req.params["token"] ?? "");
      if (!user) {
        res
          .status(404)
          .type("html")
          .send("<!doctype html><meta charset=utf-8><title>Not found</title><h1>Invalid link</h1>");
        return;
      }
      const lang = resolveLang(req, user);
      const dict = getDictForClient(lang);
      const services = user.allowedServices.map((id) => {
        const a = registry().get(id);
        return a ? { id, name: a.name } : { id, name: id };
      });
      const initial = {
        user: { id: user.id, name: user.name },
        services,
        token: req.params["token"],
        lang,
        requirePasskey: config().KNOCK_REQUIRE_PASSKEY,
      };
      res
        .type("html")
        .send(renderUserPwa({ initial, dict, lang, token: req.params["token"] ?? "" }));
    }),
  );

  router.get(
    "/u/:token/state",
    asyncH(async (req, res) => {
      const user = await userFromToken(req.params["token"]);
      const rule = await findRuleByUserId(user.id);
      const services = user.allowedServices.map((id) => {
        const a = registry().get(id);
        return a ? { id, name: a.name } : { id, name: id };
      });
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
      });
    }),
  );

  router.post(
    "/u/:token/knock",
    knockLimiter,
    asyncH(async (req, res) => {
      const user = await userFromToken(req.params["token"]);
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
        throw new HttpError(400, "IP in ignored range");
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
    "/u/:token/revoke",
    asyncH(async (req, res) => {
      const user = await userFromToken(req.params["token"]);
      const r = await revokeUser(user.id);
      res.json({ success: true, ...r });
    }),
  );

  router.get(
    "/u/:token/stats",
    asyncH(async (req, res) => {
      const user = await userFromToken(req.params["token"]);
      res.json({ success: true, stats: await summarizeUser(user.id) });
    }),
  );

  // PWA assets
  router.get("/u/:token/manifest.json", (req, res) => {
    const token = req.params["token"];
    res.json({
      name: "Game Knock",
      short_name: "Play",
      start_url: `/u/${token}`,
      scope: `/u/${token}`,
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

  router.get("/u/:token/sw.js", (_req, res) => {
    res.type("application/javascript").sendFile(path.join(PWA_DIR, "sw.js"));
  });
  router.get("/u/:token/u.js", (_req, res) => {
    res.type("application/javascript").sendFile(path.join(PWA_DIR, "u.js"));
  });
  router.get("/u/:token/u.css", (_req, res) => {
    res.type("text/css").sendFile(path.join(PWA_DIR, "u.css"));
  });

  return router;
}
