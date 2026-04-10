/**
 * Public-IP self-lookup endpoint used by the admin dashboard.
 *
 * The admin UI needs to know the household's current public IP(s) to
 * offer an "Allow my IP" button. A modern dual-stack household can have
 * *both* an IPv4 and an IPv6 address reachable at the same time (Happy
 * Eyeballs picks one per TCP connection), so we have to allow both to
 * guarantee the game client can connect.
 *
 * Resolution strategy (best-effort, returns whatever we can find):
 *   1. `req.ip` — whichever family the admin's browser is currently
 *      using to reach us. Always included if public.
 *   2. `ipv4.icanhazip.com` via an outbound HTTP request forced to
 *      IPv4 (`family: 4`). Gives us the v4 address even if the
 *      browser happened to connect over v6.
 *   3. `ipv6.icanhazip.com` via an outbound request forced to IPv6
 *      (`family: 6`). Gives us the v6 address.
 *
 * All three run in parallel with a 3-second timeout each. The response
 * is `{success, ips: string[]}` — the dashboard merges with its own
 * client-side detection (api.ipify.org / api6.ipify.org) and sends the
 * union to `/api/firewall/add`.
 */

import { Router } from "express";
import * as http from "node:http";
import { asyncH } from "../middleware/async-handler";
import { isValidPublicIP, isValidPublicIPv4, isValidPublicIPv6 } from "../lib/ip";
import { logger } from "../logger";

const UPSTREAM_TIMEOUT_MS = 3_000;

function fetchUpstream(
  host: string,
  family: 4 | 6,
  validate: (ip: string) => boolean,
): Promise<string | null> {
  return new Promise((resolve) => {
    const req = http.request(
      {
        host,
        path: "/",
        method: "GET",
        timeout: UPSTREAM_TIMEOUT_MS,
        family,
      },
      (res) => {
        if (res.statusCode !== 200) {
          res.resume();
          resolve(null);
          return;
        }
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (chunk: string) => {
          body += chunk;
          if (body.length > 64) req.destroy();
        });
        res.on("end", () => {
          const ip = body.trim();
          resolve(validate(ip) ? ip : null);
        });
      },
    );
    req.on("timeout", () => req.destroy());
    req.on("error", () => resolve(null));
    req.end();
  });
}

async function fetchUpstreamIpv4(): Promise<string | null> {
  return fetchUpstream("ipv4.icanhazip.com", 4, isValidPublicIPv4);
}

async function fetchUpstreamIpv6(): Promise<string | null> {
  return fetchUpstream("ipv6.icanhazip.com", 6, isValidPublicIPv6);
}

export function publicIpRouter(): Router {
  const router = Router();

  router.get(
    "/api/public-ip",
    asyncH(async (req, res) => {
      const found = new Set<string>();
      const push = (ip: string | null) => {
        if (ip && isValidPublicIP(ip) && !found.has(ip)) found.add(ip);
      };

      // (1) What the browser reached us as, if public.
      push((req.ip ?? "").toString());

      // (2) + (3) Parallel outbound v4 + v6 lookups. Either may fail
      // silently — e.g. an IPv4-only host can't reach
      // ipv6.icanhazip.com. fetchUpstream returns null on failure.
      const [v4, v6] = await Promise.all([
        fetchUpstreamIpv4().catch((err: Error) => {
          logger().warn({ err: err.message }, "public-ip v4 upstream failed");
          return null;
        }),
        fetchUpstreamIpv6().catch((err: Error) => {
          logger().warn({ err: err.message }, "public-ip v6 upstream failed");
          return null;
        }),
      ]);
      push(v4);
      push(v6);

      const ips = [...found];
      res.json({
        success: ips.length > 0,
        ips,
        // Back-compat: legacy clients read `.ip` — give them the first
        // entry (whichever family we found first, preferring browser).
        ip: ips[0] ?? null,
      });
    }),
  );

  return router;
}
