/**
 * Server bootstrap.
 *
 * Loads config → initialises logger → loads service registry →
 * starts stats collector + periodic expiry sweep → listens on API_PORT.
 *
 * On SIGTERM / SIGINT we drain open requests, dispose the registry
 * (closes RCON connections) and exit cleanly.
 */

import * as http from "node:http";
import { initBootstrap } from "./auth/bootstrap";
import { sweepChallenges } from "./auth/challenges";
import { config } from "./config";
import { logger } from "./logger";
import { createApp } from "./app";
import { initRegistry, disposeRegistry } from "./services/registry";
import { statsCollector } from "./stats/collector";
import { sweepExpiredRules } from "./knock/smart-revoke";
import { sweepExpiredSessions } from "./repos/admin";

async function main(): Promise<void> {
  const c = config();
  const log = logger();

  log.info(
    {
      port: c.API_PORT,
      defaultService: c.DEFAULT_SERVICE_ID,
      defaultLocale: c.DEFAULT_LOCALE,
      trustProxy: c.TRUST_PROXY,
      knockRequirePasskey: c.KNOCK_REQUIRE_PASSKEY,
    },
    "starting gamedash",
  );

  await initRegistry();
  await initBootstrap();

  statsCollector().start();

  // Periodic firewall rule expiry sweep + admin session sweep
  // + WebAuthn challenge sweep (every 10 minutes).
  const sweepInterval = setInterval(() => {
    sweepExpiredRules().catch((err: Error) =>
      log.warn({ err: err.message }, "sweep failed"),
    );
    sweepExpiredSessions().catch((err: Error) =>
      log.warn({ err: err.message }, "admin session sweep failed"),
    );
    sweepChallenges();
  }, 10 * 60 * 1000);

  const app = createApp();
  const server = http.createServer(app);

  server.listen(c.API_PORT, () => {
    log.info({ port: c.API_PORT }, "listening");
  });

  const shutdown = async (signal: string): Promise<void> => {
    log.info({ signal }, "shutting down");
    clearInterval(sweepInterval);
    statsCollector().stop();
    server.close((err) => {
      if (err) log.warn({ err: err.message }, "server close error");
    });
    try {
      await disposeRegistry();
    } catch (err) {
      log.warn({ err: (err as Error).message }, "registry dispose error");
    }
    setTimeout(() => process.exit(0), 500).unref();
  };

  process.on("SIGTERM", () => void shutdown("SIGTERM"));
  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("unhandledRejection", (reason) => {
    log.error({ reason: String(reason) }, "unhandled rejection");
  });
}

main().catch((err: Error) => {
  // eslint-disable-next-line no-console
  console.error("fatal:", err.message, err.stack);
  process.exit(1);
});
