/**
 * Operational endpoints — readiness probe + Prometheus metrics.
 *
 * These are intentionally *unauthenticated* so container orchestrators
 * can probe them without a cookie. They expose no data that isn't
 * already inferable from connecting to the service (e.g. "yes, the
 * server is running") and only count aggregate state in metrics.
 *
 * Mount this router BEFORE the admin gate in app.ts.
 */

import { Router } from "express";
import { asyncH } from "../middleware/async-handler";
import { metrics, registerRuntimeGauges } from "../metrics";
import { loadAdminSessions } from "../repos/admin";
import { loadKnockSessions } from "../repos/knock-sessions";
import { loadRules } from "../repos/firewall-rules";
import { registry } from "../services/registry";

export function installRuntimeGauges(): void {
  registerRuntimeGauges({
    countServices: () => registry().list().length,
    countAdminSessions: async () => (await loadAdminSessions()).sessions.length,
    countKnockSessions: async () => (await loadKnockSessions()).sessions.length,
    countFirewallRules: async () => (await loadRules()).rules.length,
  });
}

export function opsRouter(): Router {
  const router = Router();

  router.get(
    "/readyz",
    asyncH(async (_req, res) => {
      const checks: Record<string, { ok: boolean; message?: string }> = {};

      try {
        const services = registry().list();
        checks["registry"] = services.length > 0
          ? { ok: true }
          : { ok: false, message: "no services loaded" };
      } catch (err) {
        checks["registry"] = { ok: false, message: (err as Error).message };
      }

      try {
        await loadAdminSessions();
        checks["admin_store"] = { ok: true };
      } catch (err) {
        checks["admin_store"] = { ok: false, message: (err as Error).message };
      }

      try {
        await loadRules();
        checks["firewall_store"] = { ok: true };
      } catch (err) {
        checks["firewall_store"] = { ok: false, message: (err as Error).message };
      }

      const allOk = Object.values(checks).every((c) => c.ok);
      res.status(allOk ? 200 : 503).json({
        ok: allOk,
        ts: new Date().toISOString(),
        checks,
      });
    }),
  );

  router.get(
    "/metrics",
    asyncH(async (_req, res) => {
      const body = await metrics().expose();
      res.type("text/plain; version=0.0.4").send(body);
    }),
  );

  return router;
}
