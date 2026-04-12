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
      // Dedupe + reject any non-public address. We accept either IPv4 or
      // IPv6 — the dashboard detects both families client-side and sends
      // whichever the admin's browser picked, so we must allow both.
      const ips = [...new Set(body.ips)].filter((ip) => isValidPublicIP(ip));
      if (ips.length === 0) {
        throw new HttpError(400, "invalid or non-public IP address");
      }
      // Any overlap with an existing rule is treated as a conflict. We
      // could merge instead, but manual admin rules have a label and
      // silently merging two labelled rules hides intent.
      for (const ip of ips) {
        if (await findRuleByIp(ip)) {
          throw new HttpError(409, "IP already in allowlist");
        }
      }
      const ports = registry().collectPorts(body.services ?? null);
      if (ports.length === 0) throw new HttpError(400, "no ports resolved");
      const errors = await ufwAllowMany(ips, ports);
      await upsertRule({
        ips,
        addedAt: new Date().toISOString(),
        label: body.label ?? "",
        services: registry().buildRuleServices(body.services ?? null),
      });
      await audit({ kind: "firewall.add_manual", ips, label: body.label ?? "" });
      res.json({ success: true, ips, errors });
    }),
  );

  router.post(
    "/api/firewall/remove",
    firewallLimiter,
    asyncH(async (req, res) => {
      const body = FirewallRemoveBodySchema.parse(req.body);
      // The client can pass any IP belonging to the rule — we look it up
      // via the first match, then nuke the whole rule (all of its IPs).
      const bodyIps = body.ips.filter((ip) => isValidPublicIP(ip));
      if (bodyIps.length === 0) {
        throw new HttpError(400, "invalid or non-public IP address");
      }
      let rule = null;
      for (const ip of bodyIps) {
        rule = await findRuleByIp(ip);
        if (rule) break;
      }
      if (!rule) throw new HttpError(404, "IP not in allowlist");
      await ufwDeleteMany(rule.ips, flattenPorts(rule));
      for (const ip of rule.ips) {
        await deleteRuleByIp(ip);
      }
      await audit({ kind: "firewall.remove_manual", ips: rule.ips });
      res.json({ success: true, ips: rule.ips });
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
        const ips = rule?.ips ?? [];
        // Merge live port/proto keys across every IP in the rule — a
        // dual-stack player might be connected over v6 even though the
        // rule also holds their v4 address.
        const live = new Set<string>();
        for (const ip of ips) {
          const perIp = liveByIp.get(ip);
          if (perIp) for (const key of perIp) live.add(key);
        }
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
          ips,
          ipExpiresAt: rule?.expiresAt ?? null,
          services,
          suspended: u.suspended ?? false,
        };
      });

      res.json({ success: true, sessions });
    }),
  );

  return router;
}
