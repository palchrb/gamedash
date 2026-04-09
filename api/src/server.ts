/**
 * Server bootstrap.
 *
 * Loads config → initialises logger → loads service registry →
 * starts stats collector + periodic expiry sweep → listens on API_PORT.
 *
 * On SIGTERM / SIGINT we stop accepting new connections, let in-flight
 * requests finish (up to SHUTDOWN_GRACE_MS), dispose the registry
 * (closes RCON connections) and exit cleanly.
 */

import * as http from "node:http";
import { initBootstrap } from "./auth/bootstrap";
import { sweepChallenges } from "./auth/challenges";
import { config } from "./config";
import { logger } from "./logger";
import { createApp } from "./app";
import { installRuntimeGauges } from "./routes/ops";
import { initRegistry, disposeRegistry } from "./services/registry";
import { statsCollector } from "./stats/collector";
import { sweepExpiredRules } from "./knock/smart-revoke";
import { rotateAuditLogIfNeeded } from "./repos/audit";
import { sweepExpiredSessions } from "./repos/admin";
import { sweepExpiredKnockSessions } from "./repos/knock-sessions";

const SHUTDOWN_GRACE_MS = 10_000;

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
  installRuntimeGauges();

  statsCollector().start();

  // Periodic firewall rule expiry sweep + admin/knock session sweep
  // + WebAuthn challenge sweep + audit log rotation (every 10 minutes).
  const sweepInterval = setInterval(() => {
    sweepExpiredRules().catch((err: Error) =>
      log.warn({ err: err.message }, "sweep failed"),
    );
    sweepExpiredSessions().catch((err: Error) =>
      log.warn({ err: err.message }, "admin session sweep failed"),
    );
    sweepExpiredKnockSessions().catch((err: Error) =>
      log.warn({ err: err.message }, "knock session sweep failed"),
    );
    sweepChallenges();
    rotateAuditLogIfNeeded({
      maxBytes: c.AUDIT_LOG_MAX_BYTES,
      maxFiles: c.AUDIT_LOG_MAX_FILES,
    }).catch((err: Error) =>
      log.warn({ err: err.message }, "audit rotate failed"),
    );
  }, 10 * 60 * 1000);
  sweepInterval.unref();

  const app = createApp();
  const server = http.createServer(app);

  server.listen(c.API_PORT, () => {
    log.info({ port: c.API_PORT }, "listening");
  });

  let shuttingDown = false;
  const shutdown = async (signal: string): Promise<void> => {
    if (shuttingDown) return;
    shuttingDown = true;
    log.info({ signal }, "shutting down");
    clearInterval(sweepInterval);
    statsCollector().stop();

    // Stop accepting new connections. `server.close` fires once every
    // in-flight request has finished — we race it with a hard deadline
    // so a stuck keep-alive socket cannot delay shutdown indefinitely.
    const closed = new Promise<void>((resolve) => {
      server.close((err) => {
        if (err) log.warn({ err: err.message }, "server close error");
        resolve();
      });
    });
    const grace = new Promise<void>((resolve) =>
      setTimeout(() => {
        log.warn({ ms: SHUTDOWN_GRACE_MS }, "shutdown grace elapsed, forcing close");
        resolve();
      }, SHUTDOWN_GRACE_MS).unref(),
    );
    await Promise.race([closed, grace]);

    try {
      await disposeRegistry();
    } catch (err) {
      log.warn({ err: (err as Error).message }, "registry dispose error");
    }
    log.info("shutdown complete");
    process.exit(0);
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
