/**
 * Per-service routes: lifecycle, logs, RCON, whitelist, ops, backups, worlds.
 *
 * All routes 404 if the service id is unknown, 400 if the service does not
 * advertise the required capability. World-upload is handled separately
 * because it needs multer middleware.
 */

import { Router } from "express";
import { config } from "../config";
import { asyncH } from "../middleware/async-handler";
import { HttpError } from "../middleware/error-handler";
import { resolveMapUrl } from "./map-proxy";
import { PlayerBodySchema } from "../schemas";
import { registry } from "../services/registry";
import type { Capability, ServiceAdapter } from "../services/types";

function requireService(id: string | undefined): ServiceAdapter {
  if (!id) throw new HttpError(404, "service id missing");
  const svc = registry().get(id);
  if (!svc) throw new HttpError(404, "service not found");
  return svc;
}

function requireCapability(svc: ServiceAdapter, cap: Capability): void {
  if (!svc.hasCapability(cap)) {
    throw new HttpError(400, `service does not support ${cap}`);
  }
}

export function servicesRouter(): Router {
  const router = Router();

  router.get("/api/services", (_req, res) => {
    // Enrich each descriptor with the admin-context mapUrl so the
    // dashboard can surface a link to the proxied or external map
    // without knowing anything about the mapProxy config.
    const enriched = registry().list().map((d) => {
      const svc = registry().get(d.id);
      const mapUrl = svc ? resolveMapUrl(svc, { kind: "admin" }) : undefined;
      return mapUrl ? { ...d, mapUrl } : d;
    });
    res.json({
      success: true,
      services: enriched,
      defaultId: config().DEFAULT_SERVICE_ID,
    });
  });

  router.get(
    "/api/services/:id/status",
    asyncH(async (req, res) => {
      const svc = requireService(req.params["id"]);
      const status = await svc.status();
      res.json({ success: true, ...status });
    }),
  );

  router.post(
    "/api/services/:id/start",
    asyncH(async (req, res) => {
      const svc = requireService(req.params["id"]);
      res.json({ success: true, message: await svc.start() });
    }),
  );

  router.post(
    "/api/services/:id/stop",
    asyncH(async (req, res) => {
      const svc = requireService(req.params["id"]);
      res.json({ success: true, message: await svc.stop() });
    }),
  );

  router.post(
    "/api/services/:id/restart",
    asyncH(async (req, res) => {
      const svc = requireService(req.params["id"]);
      res.json({ success: true, message: await svc.restart() });
    }),
  );

  router.get(
    "/api/services/:id/logs",
    asyncH(async (req, res) => {
      const svc = requireService(req.params["id"]);
      requireCapability(svc, "logs");
      const linesRaw = req.query["lines"];
      const lines =
        typeof linesRaw === "string" ? Math.min(5000, Math.max(1, parseInt(linesRaw, 10) || 100)) : 100;
      res.json({ success: true, logs: await svc.logs(lines) });
    }),
  );

  router.get(
    "/api/services/:id/command/:cmd",
    asyncH(async (req, res) => {
      const svc = requireService(req.params["id"]);
      requireCapability(svc, "rcon");
      const cmd = decodeURIComponent(req.params["cmd"] ?? "");
      if (!cmd) throw new HttpError(400, "empty command");
      // This route is gated by requireAdmin (passkey session) and the
      // target RCON port is not published to the host — only reachable
      // over the internal docker network. Authenticated admins already
      // have full lifecycle control, so we deliberately don't second-
      // guess the command text here.
      res.json({ success: true, response: await svc.rconSend!(cmd) });
    }),
  );

  router.get(
    "/api/services/:id/whitelist",
    asyncH(async (req, res) => {
      const svc = requireService(req.params["id"]);
      requireCapability(svc, "whitelist");
      res.json({ success: true, response: await svc.whitelistList!() });
    }),
  );

  router.post(
    "/api/services/:id/whitelist/add",
    asyncH(async (req, res) => {
      const svc = requireService(req.params["id"]);
      requireCapability(svc, "whitelist");
      const body = PlayerBodySchema.parse(req.body);
      res.json({ success: true, response: await svc.whitelistAdd!(body.player) });
    }),
  );

  router.post(
    "/api/services/:id/whitelist/remove",
    asyncH(async (req, res) => {
      const svc = requireService(req.params["id"]);
      requireCapability(svc, "whitelist");
      const body = PlayerBodySchema.parse(req.body);
      res.json({ success: true, response: await svc.whitelistRemove!(body.player) });
    }),
  );

  router.post(
    "/api/services/:id/op",
    asyncH(async (req, res) => {
      const svc = requireService(req.params["id"]);
      requireCapability(svc, "op");
      const body = PlayerBodySchema.parse(req.body);
      res.json({ success: true, response: await svc.opAdd!(body.player) });
    }),
  );

  router.post(
    "/api/services/:id/deop",
    asyncH(async (req, res) => {
      const svc = requireService(req.params["id"]);
      requireCapability(svc, "op");
      const body = PlayerBodySchema.parse(req.body);
      res.json({ success: true, response: await svc.opRemove!(body.player) });
    }),
  );

  router.post(
    "/api/services/:id/backup",
    asyncH(async (req, res) => {
      const svc = requireService(req.params["id"]);
      requireCapability(svc, "backup");
      const info = await svc.backup!();
      res.json({ success: true, ...info });
    }),
  );

  router.get(
    "/api/services/:id/backups",
    asyncH(async (req, res) => {
      const svc = requireService(req.params["id"]);
      requireCapability(svc, "backup");
      res.json({ success: true, backups: svc.listBackups!() });
    }),
  );

  router.post(
    "/api/services/:id/backups/:name/restore",
    asyncH(async (req, res) => {
      const svc = requireService(req.params["id"]);
      requireCapability(svc, "backup");
      const name = req.params["name"];
      if (!name) throw new HttpError(400, "missing backup name");
      res.json({ success: true, ...(await svc.restoreBackup!(name)) });
    }),
  );

  router.get(
    "/api/services/:id/worlds",
    asyncH(async (req, res) => {
      const svc = requireService(req.params["id"]);
      requireCapability(svc, "worlds");
      res.json({ success: true, ...svc.listWorlds!() });
    }),
  );

  router.post(
    "/api/services/:id/worlds/save-current",
    asyncH(async (req, res) => {
      const svc = requireService(req.params["id"]);
      requireCapability(svc, "worlds");
      const name = svc.saveCurrentWorld!();
      res.json({ success: true, message: `Saved active world as ${name}` });
    }),
  );

  router.post(
    "/api/services/:id/worlds/:name/switch",
    asyncH(async (req, res) => {
      const svc = requireService(req.params["id"]);
      requireCapability(svc, "worlds");
      const name = req.params["name"];
      if (!name) throw new HttpError(400, "missing world name");
      res.json({ success: true, ...(await svc.changeWorld!(name)) });
    }),
  );

  router.post(
    "/api/services/:id/worlds/:name/new",
    asyncH(async (req, res) => {
      const svc = requireService(req.params["id"]);
      requireCapability(svc, "worlds");
      const name = req.params["name"];
      if (!name) throw new HttpError(400, "missing world name");
      res.json({ success: true, ...(await svc.newWorld!(name)) });
    }),
  );

  // TODO(phase-2): re-add world upload. The previous implementation relied
  // on a hardcoded path; we want it to go through the adapter so
  // each MC instance lands in its own worlds dir.

  return router;
}
