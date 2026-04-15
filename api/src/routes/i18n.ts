/**
 * i18n bootstrap endpoint — the client calls this once on load to get
 * the resolved language, the merged dictionary, and the list of
 * available locales.
 */

import { Router } from "express";
import { config } from "../config";
import { getDictForClient, listAvailableLocales, resolveLang } from "../lib/i18n";
import { asyncH } from "../middleware/async-handler";
import { readAndRefreshAdminSession } from "../auth/sessions";
import { findAdminById } from "../repos/admin";

export function i18nRouter(): Router {
  const router = Router();

  router.get(
    "/api/i18n",
    asyncH(async (req, res) => {
      // Opportunistic admin-session lookup — lets us honour the admin's
      // persisted locale preference on the /admin pages. Failures fall
      // through silently; /api/i18n remains usable without auth.
      let locale: string | null = null;
      try {
        const session = await readAndRefreshAdminSession(req, res);
        if (session) {
          const admin = await findAdminById(session.adminId);
          locale = admin?.locale ?? null;
        }
      } catch {
        // ignore — i18n must not hard-fail on auth issues
      }
      const lang = resolveLang(req, locale ? { locale } : null);
      res.json({
        success: true,
        lang,
        defaultLocale: config().DEFAULT_LOCALE,
        available: listAvailableLocales(),
        dict: getDictForClient(lang),
      });
    }),
  );

  return router;
}
