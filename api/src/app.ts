/**
 * Express application wiring.
 *
 * All route modules are mounted here. Middleware chain:
 *   1. trust proxy (configurable)
 *   2. pino-http request logging
 *   3. json body + cookie parser
 *   4. public routes (healthz, i18n, admin-auth)
 *   5. static admin dashboard (public/)
 *   6. static knock PWA routes under /u/:token (token-auth, not cookie)
 *   7. requireAdmin gate → all remaining /api/* routes
 *   8. central error handler (must be last)
 *
 * The admin UI itself is served as static files from `public/`. The UI
 * script is gated by requireAdmin on every API call it makes, so an
 * unauthenticated visitor gets the login page even though the HTML is
 * reachable without a cookie.
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
import { opsRouter } from "./routes/ops";
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

  // CORS — restrict to same origin. The admin UI and knock PWA are both
  // served from this same Express process, so cross-origin requests are
  // only needed if someone curls from elsewhere (which we deny).
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

  // i18n bootstrap is public so even the login page can be translated.
  app.use(i18nRouter());

  // Admin auth ceremony (bootstrap, register, login, logout, /me).
  app.use(adminAuthRouter());

  // Per-user knock PWA. Auth is carried in the URL token, not the cookie,
  // so these routes MUST be mounted before the cookie gate below.
  app.use(knockPwaRouter());

  // ── Static admin dashboard ─────────────────────────────────────────
  // Files are public (HTML/CSS/JS are not secrets); every XHR the page
  // makes goes through requireAdmin below and will 401 without a session.
  app.use(express.static(path.resolve(__dirname, "..", "public")));

  // ── Admin-gated API ────────────────────────────────────────────────
  // Global rate limiter for all admin endpoints. Endpoint-specific
  // limiters (auth, firewall writes) layer on top of this.
  app.use(
    "/api",
    rateLimit({
      windowMs: 60_000,
      max: 120,
      standardHeaders: true,
      legacyHeaders: false,
      message: { success: false, error: "too many requests" },
    }),
  );
  app.use("/api", requireAdmin);
  app.use(servicesRouter());
  app.use(usersRouter());
  app.use(directoryRouter());
  app.use(firewallRouter());
  app.use(statsRouter());
  app.use(publicIpRouter());

  // Error handler must be last
  app.use(errorHandler);

  return app;
}
