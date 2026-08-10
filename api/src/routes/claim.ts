/**
 * Share-code claim routes — the public "/c" surface.
 *
 * /c and /c/:code       → claim page (input form; :code variant prefills)
 * POST /c/lookup        → {code} → {name} for the confirm step (no consume)
 * POST /c/claim         → {code} → consumes the code, mints a fresh token,
 *                          returns it once; the browser navigates to /u/<token>
 *
 * Hardening:
 *  - The whole surface answers 404 while no claim code is outstanding —
 *    bots probing /c see nothing except during the short minting windows.
 *  - Per-IP rate limit + a global failure circuit breaker: too many bad
 *    codes across ALL IPs disables the surface for a cool-down and audits
 *    the lockout. IP limits alone don't stop distributed guessing.
 *  - Codes never appear in server responses; tokens are returned exactly
 *    once from POST (never via GET redirects, which leak into logs and
 *    get consumed by link-preview bots).
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { Router, type Request, type Response } from "express";
import rateLimit from "express-rate-limit";
import { z } from "zod";
import { asyncH } from "../middleware/async-handler";
import { clientIp } from "../lib/ip";
import { getDictForClient, resolveLang, t } from "../lib/i18n";
import { normalizeShareCode } from "../lib/hash";
import {
  anyClaimCodeOutstanding,
  claimShareCode,
  findUserByClaimCode,
} from "../repos/users";
import { audit } from "../repos/audit";

const PWA_DIR = path.resolve(__dirname, "..", "..", "pwa");

// ── Global failure circuit breaker ────────────────────────────────────
// Sliding 10-minute window of failed lookups/claims across all IPs.
// Above the threshold the surface goes dark until failures age out.
const LOCKOUT_WINDOW_MS = 10 * 60 * 1000;
const LOCKOUT_THRESHOLD = 50;
let failureTimes: number[] = [];
let lockoutAudited = false;

function pruneFailures(): void {
  const cutoff = Date.now() - LOCKOUT_WINDOW_MS;
  failureTimes = failureTimes.filter((ts) => ts > cutoff);
  if (failureTimes.length < LOCKOUT_THRESHOLD) lockoutAudited = false;
}

function isLockedOut(): boolean {
  pruneFailures();
  return failureTimes.length >= LOCKOUT_THRESHOLD;
}

function recordFailure(ip: string): void {
  failureTimes.push(Date.now());
  if (failureTimes.length >= LOCKOUT_THRESHOLD && !lockoutAudited) {
    lockoutAudited = true;
    void audit({ kind: "knock.code_lockout", lastIp: ip, failures: failureTimes.length });
  }
}

/** Test-only reset of the breaker state. */
export function resetClaimLockoutForTests(): void {
  failureTimes = [];
  lockoutAudited = false;
}

const claimLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: "too many requests" },
});

const CodeBodySchema = z.object({ code: z.string().max(64) });

let cachedClaimTemplate: string | null = null;
function renderClaimPage(params: {
  lang: string;
  dict: Record<string, string>;
  prefill: string;
}): string {
  if (!cachedClaimTemplate) {
    try {
      cachedClaimTemplate = fs.readFileSync(path.join(PWA_DIR, "claim.html"), "utf8");
    } catch {
      cachedClaimTemplate = "<!doctype html><h1>Claim template missing</h1>";
    }
  }
  const initBlob = `<script>window.__I18N__=${JSON.stringify(params.dict)};window.__INIT__=${JSON.stringify({ prefill: params.prefill })};</script>`;
  return cachedClaimTemplate
    .replace(/\{\{LANG\}\}/gu, params.lang)
    .replace(/\{\{INIT\}\}/gu, initBlob);
}

export function claimRouter(): Router {
  const router = Router();

  const servePage = asyncH(async (req: Request, res: Response) => {
    const lang = resolveLang(req);
    if (!(await anyClaimCodeOutstanding()) || isLockedOut()) {
      const title = t("claim.none_title", undefined, lang);
      const bodyText = t("claim.none_body", undefined, lang);
      res
        .status(404)
        .type("html")
        .send(
          `<!doctype html><html lang="${lang}"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${title}</title><body style="background:#0b0b1a;color:#e2e8f0;font-family:system-ui;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;text-align:center;padding:24px"><div><h1 style="color:#4ade80">${title}</h1><p style="max-width:420px">${bodyText}</p></div></body></html>`,
        );
      return;
    }
    // Prefill from the path when present; strictly sanitized, client
    // normalizes further. Never echoed anywhere else.
    const raw = req.params["code"] ?? "";
    const prefill = /^[A-Za-z0-9-]{1,16}$/u.test(raw) ? raw : "";
    res
      .type("html")
      .send(renderClaimPage({ lang, dict: getDictForClient(lang), prefill }));
  });

  router.get("/c", servePage);
  router.get("/c/:code", servePage);

  router.post(
    "/c/lookup",
    claimLimiter,
    asyncH(async (req, res) => {
      const ip = clientIp(req);
      if (isLockedOut() || !(await anyClaimCodeOutstanding())) {
        res.status(404).json({ success: false, error: "not found" });
        return;
      }
      const body = CodeBodySchema.parse(req.body);
      const normalized = normalizeShareCode(body.code);
      if (!normalized) {
        recordFailure(ip);
        res.status(400).json({ success: false, error: "invalid code" });
        return;
      }
      const user = await findUserByClaimCode(normalized);
      if (!user) {
        recordFailure(ip);
        res.status(400).json({ success: false, error: "invalid code" });
        return;
      }
      res.json({ success: true, name: user.name });
    }),
  );

  router.post(
    "/c/claim",
    claimLimiter,
    asyncH(async (req, res) => {
      const ip = clientIp(req);
      if (isLockedOut() || !(await anyClaimCodeOutstanding())) {
        res.status(404).json({ success: false, error: "not found" });
        return;
      }
      const body = CodeBodySchema.parse(req.body);
      const normalized = normalizeShareCode(body.code);
      if (!normalized) {
        recordFailure(ip);
        res.status(400).json({ success: false, error: "invalid code" });
        return;
      }
      const claimed = await claimShareCode(normalized);
      if (!claimed) {
        recordFailure(ip);
        res.status(400).json({ success: false, error: "invalid code" });
        return;
      }
      await audit({
        kind: "knock.code_claimed",
        userId: claimed.user.id,
        name: claimed.user.name,
        ip,
        ua: req.headers["user-agent"] ?? null,
      });
      res.json({ success: true, token: claimed.plainToken, name: claimed.user.name });
    }),
  );

  return router;
}
