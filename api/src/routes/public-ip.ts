/**
 * Public-IP self-lookup endpoint used by the admin dashboard.
 *
 * Returns the client's IP as seen by the server (`req.ip`). The admin
 * dashboard combines this with client-side ipify lookups to cover both
 * IPv4 and IPv6 families.
 *
 * NOTE: We intentionally do NOT make outbound requests from the server
 * to icanhazip/ipify to discover "the other" IP family. Those requests
 * would return the *server's* public IP, not the admin's — which is
 * wrong when the server runs on a remote host (cloud VPS, etc.).
 */

import { Router } from "express";
import { asyncH } from "../middleware/async-handler";
import { isValidPublicIP } from "../lib/ip";

export function publicIpRouter(): Router {
  const router = Router();

  router.get(
    "/api/public-ip",
    asyncH(async (req, res) => {
      const ip = (req.ip ?? "").toString().trim();
      const valid = isValidPublicIP(ip);
      res.json({
        success: valid,
        ips: valid ? [ip] : [],
        ip: valid ? ip : null,
      });
    }),
  );

  return router;
}
