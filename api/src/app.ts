/**
 * Express application wiring.
 *
 * All route modules are mounted here. Middleware chain:
 *   1. trust proxy (configurable)
 *   2. pino-http request logging
 *   3. json body + cookie parser
 *   4. static admin dashboard (public/)
 *   5. API routes
 *   6. central error handler (must be last)
 */

import * as path from "node:path";
import express, { type Express } from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import pinoHttp from "pino-http";
import { config } from "./config";
import { logger } from "./logger";
import { errorHandler } from "./middleware/error-handler";
import { firewallRouter } from "./routes/firewall";
import { i18nRouter } from "./routes/i18n";
import { knockPwaRouter } from "./routes/knock-pwa";
import { servicesRouter } from "./routes/services";
import { statsRouter } from "./routes/stats";
import { usersRouter } from "./routes/users";

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

  app.use(cors());
  app.use(express.json({ limit: "1mb" }));
  app.use(cookieParser());

  // Liveness probe (always public)
  app.get("/healthz", (_req, res) => {
    res.json({ ok: true, ts: new Date().toISOString() });
  });

  // Admin dashboard (static assets served before API routes)
  app.use(express.static(path.resolve(__dirname, "..", "public")));

  // API routes
  app.use(i18nRouter());
  app.use(servicesRouter());
  app.use(usersRouter());
  app.use(firewallRouter());
  app.use(statsRouter());
  app.use(knockPwaRouter());

  // Error handler must be last
  app.use(errorHandler);

  return app;
}
