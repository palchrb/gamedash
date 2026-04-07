/**
 * Lightweight i18n helper.
 *
 * Loads flat JSON dictionaries from ./locales/<lang>.json on demand.
 * Falls back to DEFAULT_LOCALE (env, default "en") and finally to "en"
 * if a key is missing in the requested language.
 *
 * Usage:
 *   const { t, resolveLang, loadLocale } = require("./i18n");
 *   t("knock.ready", { hours: 23 }, "en")
 *
 * Frontend gets the resolved dictionary inline via /api/i18n/:lang
 * (or as a script blob baked into HTML responses) so no extra fetch
 * is required at runtime.
 */

const fs = require("fs");
const path = require("path");

const LOCALES_DIR = path.join(__dirname, "locales");
const DEFAULT_LOCALE = (process.env.DEFAULT_LOCALE || "en").toLowerCase();

const cache = new Map();

function loadLocale(lang) {
  const key = (lang || "").toLowerCase() || "en";
  if (cache.has(key)) return cache.get(key);
  const file = path.join(LOCALES_DIR, `${key}.json`);
  let dict = {};
  try {
    if (fs.existsSync(file)) {
      dict = JSON.parse(fs.readFileSync(file, "utf8"));
    }
  } catch (err) {
    console.error(`i18n: failed to load ${file}:`, err.message);
  }
  cache.set(key, dict);
  return dict;
}

function listAvailableLocales() {
  try {
    return fs
      .readdirSync(LOCALES_DIR)
      .filter((f) => f.endsWith(".json"))
      .map((f) => f.replace(/\.json$/, ""));
  } catch {
    return ["en"];
  }
}

function interpolate(str, vars) {
  if (!vars) return str;
  return str.replace(/\{(\w+)\}/g, (_, name) =>
    Object.prototype.hasOwnProperty.call(vars, name) ? String(vars[name]) : `{${name}}`,
  );
}

function t(key, vars, lang) {
  const primary = loadLocale(lang || DEFAULT_LOCALE);
  if (Object.prototype.hasOwnProperty.call(primary, key)) {
    return interpolate(primary[key], vars);
  }
  // fall back to default locale
  if ((lang || "").toLowerCase() !== DEFAULT_LOCALE) {
    const fallback = loadLocale(DEFAULT_LOCALE);
    if (Object.prototype.hasOwnProperty.call(fallback, key)) {
      return interpolate(fallback[key], vars);
    }
  }
  // ultimate fallback to en.json
  if (DEFAULT_LOCALE !== "en") {
    const en = loadLocale("en");
    if (Object.prototype.hasOwnProperty.call(en, key)) {
      return interpolate(en[key], vars);
    }
  }
  // nothing found - return the key so missing translations are visible
  return key;
}

/**
 * Resolve language for an Express request.
 * Priority: explicit ?lang query → user object → Accept-Language → DEFAULT_LOCALE → "en".
 */
function resolveLang(req, user) {
  if (req && req.query && typeof req.query.lang === "string" && req.query.lang) {
    return req.query.lang.toLowerCase();
  }
  if (user && user.locale) return String(user.locale).toLowerCase();
  const header = req && req.headers && req.headers["accept-language"];
  if (header) {
    // pick first tag, e.g. "nb-NO,nb;q=0.9,en;q=0.8" → "nb"
    const first = header.split(",")[0].split(";")[0].trim().toLowerCase();
    if (first) {
      const short = first.split("-")[0];
      const available = listAvailableLocales();
      if (available.includes(first)) return first;
      if (available.includes(short)) return short;
    }
  }
  return DEFAULT_LOCALE;
}

function getDictForClient(lang) {
  // Merge default locale on top of requested locale so frontend
  // also gets fallback strings without needing two fetches.
  const out = {};
  if (DEFAULT_LOCALE !== "en") Object.assign(out, loadLocale("en"));
  Object.assign(out, loadLocale(DEFAULT_LOCALE));
  if (lang && lang !== DEFAULT_LOCALE) Object.assign(out, loadLocale(lang));
  return out;
}

module.exports = {
  t,
  resolveLang,
  loadLocale,
  listAvailableLocales,
  getDictForClient,
  DEFAULT_LOCALE,
};
