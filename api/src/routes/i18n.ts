/**
 * i18n bootstrap endpoint — the client calls this once on load to get
 * the resolved language, the merged dictionary, and the list of
 * available locales.
 */

import { Router } from "express";
import { config } from "../config";
import { getDictForClient, listAvailableLocales, resolveLang } from "../lib/i18n";

export function i18nRouter(): Router {
  const router = Router();

  router.get("/api/i18n", (req, res) => {
    const lang = resolveLang(req);
    res.json({
      success: true,
      lang,
      defaultLocale: config().DEFAULT_LOCALE,
      available: listAvailableLocales(),
      dict: getDictForClient(lang),
    });
  });

  return router;
}
