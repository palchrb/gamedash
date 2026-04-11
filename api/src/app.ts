/**
 * Express application wiring.
 *
 * All route modules are mounted here. Middleware chain:
 *   1. trust proxy (configurable)
 *   2. pino-http request logging
 *   3. json body + cookie parser
 *   4. public routes (healthz, i18n)
 *   5. admin auth routes (/admin/api/admin/*)
 *   6. knock PWA routes (/u/:token/*)
 *   7. kids portal routes (/, /portal/*, /my/*)
 *   8. static admin dashboard (/admin/)
 *   9. requireAdmin gate → all /admin/api/* routes
 *  10. central error handler (must be last)
 */

import * as path from "node:path";
import express, { type Express } from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import rateLimit from "express-rate-limit";
import pinoHttp from "pino-http";
import { requireAdmin } from "./auth/middleware";
import { config } from "./config";
import { logger } from "./logger";
import { errorHandler } from "./middleware/error-handler";
import { adminAuthRouter } from "./routes/admin-auth";
import { directoryRouter } from "./routes/directory";
import { firewallRouter } from "./routes/firewall";
import { i18nRouter } from "./routes/i18n";
import { knockPwaRouter } from "./routes/knock-pwa";
import {
  mountAdminMapProxy,
  mountPortalMapProxy,
  mountTokenMapProxy,
} from "./routes/map-proxy";
import { opsRouter } from "./routes/ops";
import { portalRouter } from "./routes/portal";
import { publicIpRouter } from "./routes/public-ip";
import { servicesRouter } from "./routes/services";
import { statsRouter } from "./routes/stats";
import { usersRouter } from "./routes/users";
import { trackHttp } from "./metrics";

export function createApp(): Express {
  const app = express();
  const c = config();

  // Reverse proxy support — required for correct req.ip with X-Forwarded-For.
  app.set("trust proxy", c.TRUST_PROXY);

  app.use(
    pinoHttp({
      logger: logger(),
      customLogLevel: (_req, res, err) => {
        if (err || res.statusCode >= 500) return "error";
        if (res.statusCode >= 400) return "warn";
        return "info";
      },
    }),
  );

  // ── Security headers ────────────────────────────────────────────────
  app.use((_req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    res.setHeader("X-XSS-Protection", "0"); // legacy; CSP is the real defence
    if (c.ADMIN_ORIGIN.startsWith("https://")) {
      res.setHeader(
        "Strict-Transport-Security",
        "max-age=63072000; includeSubDomains",
      );
    }
    next();
  });

  // CORS — restrict to same origin. The admin UI, knock PWA, and portal
  // are all served from this same Express process.
  app.use(
    cors({
      origin: c.ADMIN_ORIGIN,
      credentials: true,
    }),
  );

  app.use(express.json({ limit: "1mb" }));
  app.use(cookieParser());

  // Prometheus HTTP counter — bump on every response we ship.
  app.use((req, res, next) => {
    res.on("finish", () => {
      trackHttp(req.method, res.statusCode);
    });
    next();
  });

  // ── Always-public routes ───────────────────────────────────────────
  // Liveness probe
  app.get("/healthz", (_req, res) => {
    res.json({ ok: true, ts: new Date().toISOString() });
  });

  // Readiness probe + /metrics — kept public for orchestrator probes.
  app.use(opsRouter());

  // i18n bootstrap is public so even the login pages can be translated.
  app.use(i18nRouter());

  // Admin auth ceremony (bootstrap, register, login, logout, /me).
  // Routes live under /admin/api/admin/* but are NOT behind requireAdmin
  // since they handle their own auth.
  app.use(adminAuthRouter());

  // Per-user knock PWA. Auth is carried in the URL token, not the cookie,
  // so these routes MUST be mounted before the cookie gate below.
  app.use(knockPwaRouter());

  // ── Kids portal ────────────────────────────────────────────────────
  // Root URL (/) serves the kids portal when KNOCK_REQUIRE_PASSKEY=true,
  // or redirects to /admin otherwise. /my/* routes are authenticated via
  // gd_portal cookie.
  app.use(portalRouter());

  // ── BlueMap / web-map proxy ────────────────────────────────────────
  // Services that set `mapProxy` in services.json get proxied through
  // this origin at three auth-context-specific base paths:
  //   /admin/map/:id/*        → requireAdmin
  //   /my/map/:id/*           → portal cookie + allowedServices
  //   /u/:token/map/:id/*     → token URL + allowedServices
  // Mounted before the admin static handler so the proxy wins on
  // /admin/map/* without falling through to a static 404.
  mountAdminMapProxy(app);
  mountPortalMapProxy(app);
  mountTokenMapProxy(app);

  // ── Static admin dashboard ─────────────────────────────────────────
  // Files are public (HTML/CSS/JS are not secrets); every XHR the page
  // makes goes through requireAdmin below and will 401 without a session.
  app.use("/admin", express.static(path.resolve(__dirname, "..", "public")));

  // ── Admin-gated API ────────────────────────────────────────────────
  // Global rate limiter for all admin endpoints. Endpoint-specific
  // limiters (auth, firewall writes) layer on top of this.
  app.use(
    "/admin/api",
    rateLimit({
      windowMs: 60_000,
      max: 120,
      standardHeaders: true,
      legacyHeaders: false,
      message: { success: false, error: "too many requests" },
    }),
  );
  app.use("/admin/api", requireAdmin);
  app.use("/admin", servicesRouter());
  app.use("/admin", usersRouter());
  app.use("/admin", directoryRouter());
  app.use("/admin", firewallRouter());
  app.use("/admin", statsRouter());
  app.use("/admin", publicIpRouter());

  // Error handler must be last
  app.use(errorHandler);

  return app;
}
