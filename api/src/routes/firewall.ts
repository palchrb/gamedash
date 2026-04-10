/**
 * Admin firewall routes — list + add/remove manual rules, plus the
 * derived /api/active-sessions view that joins user records with
 * kernel connection state.
 */

import { Router } from "express";
import rateLimit from "express-rate-limit";
import { audit } from "../repos/audit";
import { asyncH } from "../middleware/async-handler";
import { HttpError } from "../middleware/error-handler";
import { clientIp, isValidPublicIP } from "../lib/ip";
import { FirewallAddBodySchema, FirewallRemoveBodySchema } from "../schemas";
import {
  deleteRuleByIp,
  findRuleByIp,
  flattenPorts,
  loadRules,
  upsertRule,
} from "../repos/firewall-rules";
import { ufwAllowMany, ufwDeleteMany } from "../firewall/ufw";
import { listAllConnections } from "../firewall/connections";
import { listUsers } from "../repos/users";
import { registry } from "../services/registry";

const firewallLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: "too many requests" },
});

export function firewallRouter(): Router {
  const router = Router();

  router.get(
    "/api/firewall",
    asyncH(async (_req, res) => {
      const data = await loadRules();
      res.json({ success: true, rules: data.rules });
    }),
  );

  router.get("/api/firewall/my-ip", (req, res) => {
    const ip = clientIp(req);
    res.json({ success: true, ip, valid: isValidPublicIP(ip) });
  });

  router.post(
    "/api/firewall/add",
    firewallLimiter,
    asyncH(async (req, res) => {
      const body = FirewallAddBodySchema.parse(req.body);
      if (!isValidPublicIP(body.ip)) {
        throw new HttpError(400, "invalid or non-public IPv4 address");
      }
      if (await findRuleByIp(body.ip)) {
        throw new HttpError(409, "IP already in allowlist");
      }
      const ports = registry().collectPorts(body.services ?? null);
      if (ports.length === 0) throw new HttpError(400, "no ports resolved");
      const errors = await ufwAllowMany(body.ip, ports);
      await upsertRule({
        ip: body.ip,
        addedAt: new Date().toISOString(),
        label: body.label ?? "",
        services: registry().buildRuleServices(body.services ?? null),
      });
      await audit({ kind: "firewall.add_manual", ip: body.ip, label: body.label ?? "" });
      res.json({ success: true, ip: body.ip, errors });
    }),
  );

  router.post(
    "/api/firewall/remove",
    firewallLimiter,
    asyncH(async (req, res) => {
      const body = FirewallRemoveBodySchema.parse(req.body);
      if (!isValidPublicIP(body.ip)) {
        throw new HttpError(400, "invalid or non-public IPv4 address");
      }
      const rule = await findRuleByIp(body.ip);
      if (!rule) throw new HttpError(404, "IP not in allowlist");
      await ufwDeleteMany(body.ip, flattenPorts(rule));
      await deleteRuleByIp(body.ip);
      await audit({ kind: "firewall.remove_manual", ip: body.ip });
      res.json({ success: true, ip: body.ip });
    }),
  );

  router.get(
    "/api/active-sessions",
    asyncH(async (_req, res) => {
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
        return {
          userId: u.id,
          name: u.name,
          ip,
          ipExpiresAt: rule?.expiresAt ?? null,
          services,
        };
      });

      res.json({ success: true, sessions });
    }),
  );

  return router;
}
