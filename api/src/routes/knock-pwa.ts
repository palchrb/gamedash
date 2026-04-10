/**
 * Per-user knock PWA routes.
 *
 * /u/:token                        → server-rendered PWA HTML (inlined i18n + init)
 * /u/:token/state                  → current active rule, allowed services, auth status
 * /u/:token/knock                  → auto-knock entry point with smart-revoke
 * /u/:token/revoke                 → user-initiated revoke
 * /u/:token/stats                  → user's own playtime summary
 * /u/:token/manifest.json          → per-user PWA manifest (scoped to token)
 * /u/:token/sw.js                  → service worker (static, cached)
 * /u/:token/u.js                   → PWA client script (static, cached)
 * /u/:token/u.css                  → PWA stylesheet (static, cached)
 * /u/:token/webauthn.js            → shared WebAuthn browser helper
 * /u/:token/webauthn/register/*    → passkey registration (opens in reg window)
 * /u/:token/webauthn/authenticate/* → passkey login → issues knock session cookie
 * /u/:token/logout                 → destroys knock session cookie
 *
 * Token in URL is still the primary bearer of identity: it resolves which
 * child a request belongs to. When KNOCK_REQUIRE_PASSKEY=true the knock
 * endpoint additionally requires a valid cookie-backed knock session.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { Router } from "express";
import rateLimit from "express-rate-limit";
import { z } from "zod";
import { asyncH } from "../middleware/async-handler";
import { HttpError } from "../middleware/error-handler";
import { clientIp, isInIgnoredRange, isValidPublicIP } from "../lib/ip";
import { getDictForClient, resolveLang } from "../lib/i18n";
import { knockUser, revokeUser } from "../knock/smart-revoke";
import { findByToken, listUsers } from "../repos/users";
import { findRuleByUserId, loadRules } from "../repos/firewall-rules";
import { summarizeUser } from "../repos/stats";
import { listAllConnections } from "../firewall/connections";
import { registry } from "../services/registry";
import { config } from "../config";
import {
  generateKnockAuthenticationOpts,
  generateKnockRegistrationOpts,
  isRegistrationOpen,
  verifyKnockAuthentication,
  verifyKnockRegistration,
} from "../auth/knock-passkey";
import {
  destroyKnockSession,
  issueKnockSession,
  readAndRefreshKnockSession,
} from "../auth/knock-sessions";
import { audit } from "../repos/audit";
import { authFailures, incCounter, knockAttempts, knockLogins } from "../metrics";
import type { UserRecord } from "../schemas";

const PWA_DIR = path.resolve(__dirname, "..", "..", "pwa");
const WEBAUTHN_JS = path.resolve(__dirname, "..", "..", "public", "webauthn.js");

const knockLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: "too many requests" },
});

const webauthnLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: "too many auth requests" },
});

async function userFromToken(token: string | undefined): Promise<UserRecord> {
  if (!token) throw new HttpError(404, "invalid token");
  const user = await findByToken(token);
  if (!user) throw new HttpError(404, "invalid token");
  return user;
}

/**
 * Enforce the optional passkey gate. Returns the validated session (or
 * null if passkey auth is disabled). Throws 401 if a session is required
 * and missing/invalid.
 */
async function requireKnockAuthIfEnabled(
  user: UserRecord,
  token: string,
  req: Parameters<typeof readAndRefreshKnockSession>[0],
  res: Parameters<typeof readAndRefreshKnockSession>[1],
): Promise<void> {
  if (!config().KNOCK_REQUIRE_PASSKEY) return;
  const session = await readAndRefreshKnockSession(req, res, token);
  if (!session || session.userId !== user.id) {
    incCounter(authFailures, { kind: "knock" });
    throw new HttpError(401, "passkey login required");
  }
}

let cachedPwaTemplate: string | null = null;
export function renderUserPwa(params: {
  initial: Record<string, unknown>;
  dict: Record<string, string>;
  lang: string;
  base: string;
}): string {
  if (!cachedPwaTemplate) {
    try {
      cachedPwaTemplate = fs.readFileSync(path.join(PWA_DIR, "index.html"), "utf8");
    } catch {
      cachedPwaTemplate = "<!doctype html><h1>PWA template missing</h1>";
    }
  }
  const initBlob = `<script>window.__I18N__=${JSON.stringify(params.dict)};window.__INIT__=${JSON.stringify(params.initial)};</script>`;
  return cachedPwaTemplate
    .replace(/\{\{LANG\}\}/gu, params.lang)
    .replace(/\{\{BASE\}\}/gu, params.base)
    .replace(/\{\{INIT\}\}/gu, initBlob);
}

const RegisterVerifyBodySchema = z.object({
  deviceLabel: z.string().max(64).optional(),
  response: z.unknown(),
});

const AuthenticateVerifyBodySchema = z.object({
  response: z.unknown(),
});

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
      const c = config();
      const initial = {
        user: { id: user.id, name: user.name },
        services,
        token: req.params["token"],
        lang,
        requirePasskey: c.KNOCK_REQUIRE_PASSKEY,
        hasCredentials: user.credentials.length > 0,
        registrationOpen: isRegistrationOpen(user),
      };
      res
        .type("html")
        .send(renderUserPwa({ initial, dict, lang, base: `/u/${req.params["token"] ?? ""}` }));
    }),
  );

  router.get(
    "/u/:token/state",
    asyncH(async (req, res) => {
      const user = await userFromToken(req.params["token"]);
      const rule = await findRuleByUserId(user.id);
      const services = user.allowedServices.map((id) => {
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

      const c = config();
      let sessionValid = false;
      if (c.KNOCK_REQUIRE_PASSKEY) {
        const session = await readAndRefreshKnockSession(req, res, req.params["token"] ?? "");
        sessionValid = !!session && session.userId === user.id;
      }

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
          requirePasskey: c.KNOCK_REQUIRE_PASSKEY,
          hasCredentials: user.credentials.length > 0,
          registrationOpen: isRegistrationOpen(user),
          sessionValid,
        },
      });
    }),
  );

  router.post(
    "/u/:token/knock",
    knockLimiter,
    asyncH(async (req, res) => {
      const user = await userFromToken(req.params["token"]);
      await requireKnockAuthIfEnabled(user, req.params["token"] ?? "", req, res);
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
        // IP is in a range where firewall rules don't make sense
        // (e.g. CGNAT, Tailscale). Return success without creating a rule.
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
    "/u/:token/revoke",
    asyncH(async (req, res) => {
      const user = await userFromToken(req.params["token"]);
      await requireKnockAuthIfEnabled(user, req.params["token"] ?? "", req, res);
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

  // Return the client's public IP — used by the anchor-IP guard in the
  // PWA so it doesn't need to call external services (which get blocked
  // by tracking protection / CORS).
  router.get(
    "/u/:token/my-ip",
    asyncH(async (req, res) => {
      await userFromToken(req.params["token"]);
      const ip = clientIp(req);
      res.json({ success: true, ip: isValidPublicIP(ip) ? ip : null });
    }),
  );

  // Family active-sessions view — shows all users' connection status
  router.get(
    "/u/:token/active",
    asyncH(async (req, res) => {
      await userFromToken(req.params["token"]); // validate token
      const fw = await loadRules();
      const users = await listUsers();
      const allPorts = registry().collectPorts();
      const conns = await listAllConnections(allPorts);
      const liveByIp = new Map<string, Set<string>>();
      for (const c of conns) {
        const set = liveByIp.get(c.srcIp) ?? new Set<string>();
        set.add(`${c.dstPort}/${c.proto}`);
        liveByIp.set(c.srcIp, set);
      }

      const playersByService: Record<string, string[]> = {};
      for (const svc of registry().services.values()) {
        if (svc.hasCapability("rcon") && svc.isRconConnected?.()) {
          try {
            const r = await svc.rconSend!("list");
            const m = r.match(/There are \d+ of a max of \d+ players online:(.*)/u);
            if (m && m[1]) {
              playersByService[svc.id] = m[1]
                .split(",")
                .map((p) => p.trim())
                .filter(Boolean);
            }
          } catch {
            // ignore
          }
        }
      }

      const sessions = users.map((u) => {
        const rule = fw.rules.find((r) => r.userId === u.id);
        const ip = rule?.ip ?? null;
        const live = ip ? liveByIp.get(ip) ?? new Set<string>() : new Set<string>();
        const services = u.allowedServices.map((sid) => {
          const adapter = registry().get(sid);
          const ports = adapter?.ports ?? [];
          const connected = ports.some((p) => live.has(`${p.port}/${p.proto}`));
          return {
            id: sid,
            name: adapter?.name ?? sid,
            connected,
            playerNames: playersByService[sid] ?? [],
          };
        });
        return { userId: u.id, name: u.name, ip, services };
      });

      res.json({ success: true, sessions });
    }),
  );

  // ── WebAuthn ──────────────────────────────────────────────────────────

  router.post(
    "/u/:token/webauthn/register/options",
    webauthnLimiter,
    asyncH(async (req, res) => {
      const user = await userFromToken(req.params["token"]);
      if (!isRegistrationOpen(user) && user.credentials.length > 0) {
        throw new HttpError(403, "registration window closed");
      }
      const options = await generateKnockRegistrationOpts(user);
      res.json({ success: true, options });
    }),
  );

  router.post(
    "/u/:token/webauthn/register/verify",
    webauthnLimiter,
    asyncH(async (req, res) => {
      const user = await userFromToken(req.params["token"]);
      if (!isRegistrationOpen(user) && user.credentials.length > 0) {
        throw new HttpError(403, "registration window closed");
      }
      const body = RegisterVerifyBodySchema.parse(req.body);
      try {
        await verifyKnockRegistration({
          userId: user.id,
          response: body.response,
          ...(body.deviceLabel !== undefined ? { deviceLabel: body.deviceLabel } : {}),
        });
      } catch (err) {
        throw new HttpError(400, (err as Error).message);
      }
      // Log them in immediately so they don't need to redo the ceremony.
      await issueKnockSession(res, req, {
        userId: user.id,
        token: req.params["token"] ?? "",
      });
      await audit({
        kind: "knock.credential_added",
        userId: user.id,
        deviceLabel: body.deviceLabel ?? null,
      });
      res.json({ success: true });
    }),
  );

  router.post(
    "/u/:token/webauthn/authenticate/options",
    webauthnLimiter,
    asyncH(async (req, res) => {
      const user = await userFromToken(req.params["token"]);
      if (user.credentials.length === 0) {
        throw new HttpError(400, "no credentials registered");
      }
      const options = await generateKnockAuthenticationOpts(user);
      res.json({ success: true, options });
    }),
  );

  router.post(
    "/u/:token/webauthn/authenticate/verify",
    webauthnLimiter,
    asyncH(async (req, res) => {
      const user = await userFromToken(req.params["token"]);
      const body = AuthenticateVerifyBodySchema.parse(req.body);
      try {
        await verifyKnockAuthentication({ user, response: body.response });
      } catch (err) {
        incCounter(authFailures, { kind: "knock" });
        throw new HttpError(401, (err as Error).message);
      }
      await issueKnockSession(res, req, {
        userId: user.id,
        token: req.params["token"] ?? "",
      });
      await audit({ kind: "knock.login", userId: user.id });
      incCounter(knockLogins);
      res.json({ success: true });
    }),
  );

  router.post(
    "/u/:token/logout",
    asyncH(async (req, res) => {
      await destroyKnockSession(req, res, req.params["token"] ?? "");
      res.json({ success: true });
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
      background_color: "#0b0b1a",
      theme_color: "#0b0b1a",
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
  router.get("/u/:token/webauthn.js", (_req, res) => {
    res.type("application/javascript").sendFile(WEBAUTHN_JS);
  });

  return router;
}
