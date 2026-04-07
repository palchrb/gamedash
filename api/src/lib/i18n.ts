/**
 * Lightweight i18n helper.
 *
 * Loads flat JSON dictionaries from ./locales/<lang>.json on demand.
 * Falls back to DEFAULT_LOCALE (env, default "en") and finally to "en".
 *
 * Works both on the server (for error messages + PWA server-render) and
 * is shipped to the frontend as a pre-merged dictionary via /api/i18n so
 * no extra fetches are needed at runtime.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { Request } from "express";
import { config } from "../config";

const LOCALES_DIR = path.resolve(__dirname, "..", "..", "locales");

type Dict = Record<string, string>;
const cache = new Map<string, Dict>();

export function loadLocale(lang: string): Dict {
  const key = lang.toLowerCase() || "en";
  const cached = cache.get(key);
  if (cached) return cached;
  const file = path.join(LOCALES_DIR, `${key}.json`);
  let dict: Dict = {};
  try {
    if (fs.existsSync(file)) {
      dict = JSON.parse(fs.readFileSync(file, "utf8")) as Dict;
    }
  } catch (err) {
    // Swallow at init; we don't want a broken locale to crash the server.
    // The caller will see untranslated keys which makes the problem obvious.
    console.error(`i18n: failed to load ${file}:`, (err as Error).message);
  }
  cache.set(key, dict);
  return dict;
}

export function listAvailableLocales(): string[] {
  try {
    return fs
      .readdirSync(LOCALES_DIR)
      .filter((f) => f.endsWith(".json"))
      .map((f) => f.replace(/\.json$/u, ""));
  } catch {
    return ["en"];
  }
}

function interpolate(str: string, vars?: Record<string, unknown>): string {
  if (!vars) return str;
  return str.replace(/\{(\w+)\}/gu, (_, name: string) =>
    Object.prototype.hasOwnProperty.call(vars, name) ? String(vars[name]) : `{${name}}`,
  );
}

export function t(
  key: string,
  vars?: Record<string, unknown>,
  lang?: string,
): string {
  const c = config();
  const primary = loadLocale(lang ?? c.DEFAULT_LOCALE);
  if (Object.prototype.hasOwnProperty.call(primary, key)) {
    return interpolate(primary[key]!, vars);
  }
  if ((lang ?? "").toLowerCase() !== c.DEFAULT_LOCALE) {
    const fallback = loadLocale(c.DEFAULT_LOCALE);
    if (Object.prototype.hasOwnProperty.call(fallback, key)) {
      return interpolate(fallback[key]!, vars);
    }
  }
  if (c.DEFAULT_LOCALE !== "en") {
    const en = loadLocale("en");
    if (Object.prototype.hasOwnProperty.call(en, key)) {
      return interpolate(en[key]!, vars);
    }
  }
  return key;
}

interface UserLike {
  locale?: string | null;
}

/**
 * Resolve language for an Express request.
 * Priority: ?lang query → user.locale → Accept-Language → DEFAULT_LOCALE → "en".
 */
export function resolveLang(req: Request, user?: UserLike | null): string {
  const c = config();
  const queryLang = req.query["lang"];
  if (typeof queryLang === "string" && queryLang) return queryLang.toLowerCase();
  if (user?.locale) return user.locale.toLowerCase();
  const header = req.headers["accept-language"];
  if (typeof header === "string" && header) {
    const first = header.split(",")[0]!.split(";")[0]!.trim().toLowerCase();
    if (first) {
      const short = first.split("-")[0]!;
      const available = listAvailableLocales();
      if (available.includes(first)) return first;
      if (available.includes(short)) return short;
    }
  }
  return c.DEFAULT_LOCALE;
}

/** Pre-merge dictionary for the client so the frontend needs one fetch. */
export function getDictForClient(lang: string): Dict {
  const c = config();
  const out: Dict = {};
  if (c.DEFAULT_LOCALE !== "en") Object.assign(out, loadLocale("en"));
  Object.assign(out, loadLocale(c.DEFAULT_LOCALE));
  if (lang && lang !== c.DEFAULT_LOCALE) Object.assign(out, loadLocale(lang));
  return out;
}
