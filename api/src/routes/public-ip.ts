/**
 * Public-IP self-lookup endpoint used by the admin dashboard.
 *
 * The admin UI needs to know the household's current public IP to offer
 * an "Allow my IP" button. Historically it called three different
 * browser-reachable services (ipify, etc.) which (a) leaks the admin's
 * browser to third parties and (b) breaks on corporate networks that
 * block those services.
 *
 * This endpoint resolves the IP server-side via upstream, then returns
 * it. If the server sits behind a reverse proxy that forwards
 * X-Forwarded-For (controlled by TRUST_PROXY) req.ip already gives the
 * correct value for the tab that loaded the dashboard. Otherwise we
 * fall back to an outbound lookup against icanhazip.com over IPv4.
 *
 * The outbound fallback uses a 3-second timeout and gracefully returns
 * `{success:false}` if it fails — the admin can still paste an IP by
 * hand.
 */

import { Router } from "express";
import * as http from "node:http";
import { asyncH } from "../middleware/async-handler";
import { isValidPublicIPv4 } from "../lib/ip";
import { logger } from "../logger";

const UPSTREAM_HOST = "ipv4.icanhazip.com";
const UPSTREAM_TIMEOUT_MS = 3_000;

async function fetchUpstreamIp(): Promise<string | null> {
  return new Promise((resolve) => {
    const req = http.request(
      {
        host: UPSTREAM_HOST,
        path: "/",
        method: "GET",
        timeout: UPSTREAM_TIMEOUT_MS,
        family: 4,
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
          resolve(isValidPublicIPv4(ip) ? ip : null);
        });
      },
    );
    req.on("timeout", () => req.destroy());
    req.on("error", () => resolve(null));
    req.end();
  });
}

export function publicIpRouter(): Router {
  const router = Router();

  router.get(
    "/api/public-ip",
    asyncH(async (req, res) => {
      // First prefer the ip the admin's browser is reaching us from,
      // if it's routable. That's the most accurate value — no extra
      // round-trip needed.
      const clientIp = (req.ip ?? "").toString();
      if (isValidPublicIPv4(clientIp)) {
        res.json({ success: true, ip: clientIp, source: "client" });
        return;
      }

      // Otherwise ask an upstream service.
      try {
        const ip = await fetchUpstreamIp();
        if (ip) {
          res.json({ success: true, ip, source: "upstream" });
          return;
        }
      } catch (err) {
        logger().warn(
          { err: (err as Error).message },
          "public-ip upstream lookup failed",
        );
      }
      res.json({ success: false, ip: null });
    }),
  );

  return router;
}
