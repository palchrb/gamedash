/**
 * Minecraft / Multi-Game Dashboard API
 *
 * Runs as its own Docker container in a stack with one or more managed game
 * containers (itzg/minecraft-server, impostor/impostor-server, etc.). Each
 * managed service is described by an entry in /mcdata/services.json and
 * exposed via:
 *
 *   - /api/services                              list services
 *   - /api/services/:id/status|start|stop|...    per-service operations
 *   - /api/...                                   legacy single-MC routes
 *                                                 (proxied to DEFAULT_SERVICE_ID)
 *   - /api/users (CRUD), /u/:token/*             per-child knock + PWA
 *   - /api/firewall, /api/active-sessions        firewall + live state
 *
 * The knock-PWA on /u/:token is server-rendered from api/pwa/. The
 * legacy admin dashboard lives in api/public/.
 */

require("dotenv").config();
const express = require("express");
const fs = require("fs-extra");
const cors = require("cors");
const multer = require("multer");
const rateLimit = require("express-rate-limit");
const path = require("path");
const { exec } = require("child_process");
const { createProxyMiddleware } = require("http-proxy-middleware");

const { Registry, DEFAULT_SERVICE_ID } = require("./registry");
const firewall = require("./firewall");
const users = require("./users");
const stats = require("./stats");
const connections = require("./connections");
const i18n = require("./i18n");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const API_PORT = 3000;
const UPLOADS_DIR = "/mcdata/uploads";
const KNOCK_PORT = parseInt(process.env.KNOCK_PORT, 10) || 8100;
const BLUEMAP_HOST = process.env.BLUEMAP_HOST || "";

// CIDR ranges to silently ignore for knocks (legacy env var)
const KNOCK_IGNORE_RANGES = (process.env.KNOCK_IGNORE_RANGES || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean)
  .map((cidr) => {
    const [net, bits] = cidr.split("/");
    const parts = net.split(".").map(Number);
    const ip32 =
      ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
    const mask = bits ? (~0 << (32 - parseInt(bits, 10))) >>> 0 : 0xffffffff;
    return { ip32, mask };
  });

function isIgnoredRange(ip) {
  const parts = ip.split(".").map(Number);
  const ip32 =
    ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
  return KNOCK_IGNORE_RANGES.some((r) => (ip32 & r.mask) === (r.ip32 & r.mask));
}

fs.ensureDirSync(UPLOADS_DIR);
const upload = multer({ dest: UPLOADS_DIR });

// ---------------------------------------------------------------------------
// Service registry boot
// ---------------------------------------------------------------------------

const registry = new Registry().load();

function defaultAdapter() {
  const a = registry.getDefault();
  if (!a) throw new Error("No services configured");
  return a;
}

// Auto-migrate legacy firewall rules so old single-MC deployments keep working
firewall.migrateLegacyRules(registry.collectPorts());

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function clientIp(req) {
  return (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "")
    .split(",")[0]
    .trim()
    .replace(/^::ffff:/, "");
}

function lang(req, user) {
  return i18n.resolveLang(req, user);
}

function tr(req, key, vars, user) {
  return i18n.t(key, vars, lang(req, user));
}

function asyncH(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch((err) => {
      console.error(`[${req.method} ${req.path}]`, err.message);
      res.status(500).json({ success: false, error: err.message });
    });
  };
}

// ---------------------------------------------------------------------------
// i18n endpoint
// ---------------------------------------------------------------------------

app.get("/api/i18n", (req, res) => {
  const l = lang(req);
  res.json({
    success: true,
    lang: l,
    defaultLocale: i18n.DEFAULT_LOCALE,
    available: i18n.listAvailableLocales(),
    dict: i18n.getDictForClient(l),
  });
});

// ---------------------------------------------------------------------------
// Services registry endpoints
// ---------------------------------------------------------------------------

app.get("/api/services", (req, res) => {
  res.json({ success: true, services: registry.list(), defaultId: DEFAULT_SERVICE_ID });
});

function serviceFromReq(req, res) {
  const adapter = registry.get(req.params.id);
  if (!adapter) {
    res.status(404).json({ success: false, error: tr(req, "error.service_not_found") });
    return null;
  }
  return adapter;
}

// Generic per-service operations (delegate to adapter)
app.get("/api/services/:id/status", asyncH(async (req, res) => {
  const s = serviceFromReq(req, res); if (!s) return;
  res.json({ success: true, ...(await s.status()) });
}));

app.post("/api/services/:id/start", asyncH(async (req, res) => {
  const s = serviceFromReq(req, res); if (!s) return;
  res.json({ success: true, message: await s.start() });
}));

app.post("/api/services/:id/stop", asyncH(async (req, res) => {
  const s = serviceFromReq(req, res); if (!s) return;
  res.json({ success: true, message: await s.stop() });
}));

app.post("/api/services/:id/restart", asyncH(async (req, res) => {
  const s = serviceFromReq(req, res); if (!s) return;
  res.json({ success: true, message: await s.restart() });
}));

app.get("/api/services/:id/logs", asyncH(async (req, res) => {
  const s = serviceFromReq(req, res); if (!s) return;
  res.json({ success: true, logs: await s.logs(parseInt(req.query.lines, 10) || 100) });
}));

app.get("/api/services/:id/command/:cmd", asyncH(async (req, res) => {
  const s = serviceFromReq(req, res); if (!s) return;
  if (!s.hasCapability("rcon")) {
    return res.status(400).json({ success: false, error: "Service does not support RCON" });
  }
  res.json({ success: true, response: await s.rconSend(decodeURIComponent(req.params.cmd)) });
}));

app.get("/api/services/:id/whitelist", asyncH(async (req, res) => {
  const s = serviceFromReq(req, res); if (!s) return;
  if (!s.hasCapability("whitelist")) return res.status(400).json({ success: false, error: "unsupported" });
  res.json({ success: true, response: await s.whitelistList() });
}));
app.post("/api/services/:id/whitelist/add", asyncH(async (req, res) => {
  const s = serviceFromReq(req, res); if (!s) return;
  if (!req.body.player) return res.status(400).json({ success: false, error: "Missing player" });
  res.json({ success: true, response: await s.whitelistAdd(req.body.player) });
}));
app.post("/api/services/:id/whitelist/remove", asyncH(async (req, res) => {
  const s = serviceFromReq(req, res); if (!s) return;
  if (!req.body.player) return res.status(400).json({ success: false, error: "Missing player" });
  res.json({ success: true, response: await s.whitelistRemove(req.body.player) });
}));
app.post("/api/services/:id/op", asyncH(async (req, res) => {
  const s = serviceFromReq(req, res); if (!s) return;
  if (!req.body.player) return res.status(400).json({ success: false, error: "Missing player" });
  res.json({ success: true, response: await s.opAdd(req.body.player) });
}));
app.post("/api/services/:id/deop", asyncH(async (req, res) => {
  const s = serviceFromReq(req, res); if (!s) return;
  if (!req.body.player) return res.status(400).json({ success: false, error: "Missing player" });
  res.json({ success: true, response: await s.opRemove(req.body.player) });
}));

app.get("/api/services/:id/backup", asyncH(async (req, res) => {
  const s = serviceFromReq(req, res); if (!s) return;
  if (!s.hasCapability("backup")) return res.status(400).json({ success: false, error: "unsupported" });
  res.json({ success: true, ...(await s.backup()) });
}));
app.get("/api/services/:id/list-backups", asyncH(async (req, res) => {
  const s = serviceFromReq(req, res); if (!s) return;
  res.json({ success: true, backups: s.listBackups() });
}));
app.get("/api/services/:id/restore-backup/:name", asyncH(async (req, res) => {
  const s = serviceFromReq(req, res); if (!s) return;
  res.json({ success: true, ...(await s.restoreBackup(req.params.name)) });
}));
app.get("/api/services/:id/list-worlds", asyncH(async (req, res) => {
  const s = serviceFromReq(req, res); if (!s) return;
  res.json({ success: true, ...s.listWorlds() });
}));
app.get("/api/services/:id/save-current", asyncH(async (req, res) => {
  const s = serviceFromReq(req, res); if (!s) return;
  const name = s.saveCurrentWorld();
  res.json({ success: true, message: `Saved active world to worlds/${name}` });
}));
app.get("/api/services/:id/change-world/:name", asyncH(async (req, res) => {
  const s = serviceFromReq(req, res); if (!s) return;
  res.json({ success: true, ...(await s.changeWorld(req.params.name)) });
}));
app.get("/api/services/:id/new-world/:name", asyncH(async (req, res) => {
  const s = serviceFromReq(req, res); if (!s) return;
  res.json({ success: true, ...(await s.newWorld(req.params.name)) });
}));

// ---------------------------------------------------------------------------
// Legacy single-MC routes — proxy to DEFAULT_SERVICE_ID (mc1) for back compat
// ---------------------------------------------------------------------------

app.get("/api/status", asyncH(async (req, res) => {
  try {
    const s = defaultAdapter();
    const st = await s.status();
    res.json({
      status: st.running ? "started" : "stopped",
      online: st.players.length,
      players: st.players,
      currentWorld: st.details.currentWorld || null,
    });
  } catch {
    res.json({ status: "stopped", online: 0, players: [], currentWorld: null });
  }
}));

app.get("/api/rcon-status", (req, res) => {
  try {
    res.json({ connected: defaultAdapter().isRconConnected() });
  } catch {
    res.json({ connected: false });
  }
});

app.get("/api/start", asyncH(async (req, res) => {
  await defaultAdapter().start();
  res.json({ success: true, message: "Server starting - RCON ready in ~40s" });
}));

app.get("/api/stop", asyncH(async (req, res) => {
  await defaultAdapter().stop();
  res.json({ success: true, message: "Server stopping..." });
}));

app.get("/api/command/:cmd", asyncH(async (req, res) => {
  const r = await defaultAdapter().rconSend(decodeURIComponent(req.params.cmd));
  res.json({ success: true, response: r });
}));

app.get("/api/gamemode-all/:mode", asyncH(async (req, res) => {
  const adapter = defaultAdapter();
  const listResp = await adapter.rconSend("list");
  const playersStr = listResp.split(":")[1] || "";
  const players = playersStr.split(",").map((p) => p.trim()).filter(Boolean);
  for (const player of players) {
    await adapter.rconSend(`gamemode ${req.params.mode} ${player}`);
  }
  res.json({
    success: true,
    message: `Gamemode ${req.params.mode} set for: ${players.join(", ") || "no players online"}`,
  });
}));

app.get("/api/whitelist", asyncH(async (req, res) => {
  res.json({ success: true, response: await defaultAdapter().whitelistList() });
}));
app.post("/api/whitelist/add", asyncH(async (req, res) => {
  if (!req.body.player) return res.status(400).json({ error: "Missing player name" });
  res.json({ success: true, response: await defaultAdapter().whitelistAdd(req.body.player) });
}));
app.post("/api/whitelist/remove", asyncH(async (req, res) => {
  if (!req.body.player) return res.status(400).json({ error: "Missing player name" });
  res.json({ success: true, response: await defaultAdapter().whitelistRemove(req.body.player) });
}));
app.post("/api/op", asyncH(async (req, res) => {
  if (!req.body.player) return res.status(400).json({ error: "Missing player name" });
  res.json({ success: true, response: await defaultAdapter().opAdd(req.body.player) });
}));
app.post("/api/deop", asyncH(async (req, res) => {
  if (!req.body.player) return res.status(400).json({ error: "Missing player name" });
  res.json({ success: true, response: await defaultAdapter().opRemove(req.body.player) });
}));
app.get("/api/backup", asyncH(async (req, res) => {
  const r = await defaultAdapter().backup();
  res.json({ success: true, message: `Backup saved: ${r.name}` });
}));
app.get("/api/list-backups", (req, res) => {
  res.json({ backups: defaultAdapter().listBackups() });
});
app.get("/api/list-worlds", (req, res) => {
  res.json(defaultAdapter().listWorlds());
});
app.get("/api/save-current", asyncH(async (req, res) => {
  const name = defaultAdapter().saveCurrentWorld();
  res.json({ success: true, message: `Saved active world to worlds/${name}` });
}));
app.get("/api/change-world/:worldName", asyncH(async (req, res) => {
  const r = await defaultAdapter().changeWorld(req.params.worldName);
  res.json({ success: true, message: `Switching to ${r.switching}... server restarting` });
}));
app.get("/api/new-world/:worldName", asyncH(async (req, res) => {
  const r = await defaultAdapter().newWorld(req.params.worldName);
  res.json({ success: true, message: `Creating new world: ${r.creating}. Server restarting...` });
}));
app.get("/api/restore-backup/:backupName", asyncH(async (req, res) => {
  const r = await defaultAdapter().restoreBackup(req.params.backupName);
  res.json({ success: true, message: `Restoring backup: ${r.restoring}. Server restarting...` });
}));

app.post("/api/upload-world", upload.single("worldFile"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file uploaded" });
  const adapter = defaultAdapter();
  const baseName = req.file.originalname.replace(/\.[^/.]+$/, "");
  const newWorldPath = path.join(adapter.worldsDir, baseName);

  if (fs.existsSync(newWorldPath)) {
    fs.unlinkSync(req.file.path);
    return res.status(409).json({ error: `World "${baseName}" already exists` });
  }
  exec(
    `unzip -o "${req.file.path}" -d "${newWorldPath}" && rm "${req.file.path}"`,
    (error) => {
      if (error) {
        try { fs.unlinkSync(req.file.path); } catch {}
        return res.status(500).json({ error: "Failed to extract world zip" });
      }
      const contents = fs.readdirSync(newWorldPath);
      if (contents.length === 1) {
        const inner = path.join(newWorldPath, contents[0]);
        if (fs.statSync(inner).isDirectory() && fs.existsSync(path.join(inner, "level.dat"))) {
          const tmpPath = `${newWorldPath}_tmp`;
          fs.moveSync(inner, tmpPath);
          fs.rmSync(newWorldPath, { recursive: true, force: true });
          fs.moveSync(tmpPath, newWorldPath);
        }
      }
      res.json({ success: true, message: `World "${baseName}" uploaded and ready` });
    },
  );
});

app.get("/api/logs", asyncH(async (req, res) => {
  const lines = parseInt(req.query.lines, 10) || 50;
  res.json({ logs: await defaultAdapter().logs(lines) });
}));

// ---------------------------------------------------------------------------
// Firewall (generalized over all configured services)
// ---------------------------------------------------------------------------

const firewallLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: "Too many requests, try again later" },
});

app.get("/api/firewall", (req, res) => {
  res.json({ success: true, rules: firewall.loadRules().rules });
});

app.get("/api/firewall/my-ip", (req, res) => {
  const ip = clientIp(req);
  res.json({ success: true, ip, valid: firewall.isValidPublicIPv4(ip) });
});

app.post("/api/firewall/add", firewallLimiter, asyncH(async (req, res) => {
  const { ip, label, services } = req.body;
  if (!ip || !firewall.isValidPublicIPv4(ip)) {
    return res.status(400).json({ success: false, error: tr(req, "error.invalid_ip") });
  }
  if (firewall.findRuleByIp(ip)) {
    return res.status(409).json({ success: false, error: tr(req, "error.ip_in_use") });
  }
  const ports = registry.collectPorts(services || null);
  await firewall.ufwAllowMany(ip, ports);
  firewall.upsertRule({
    ip,
    addedAt: new Date().toISOString(),
    label: label || "",
    services: registry.buildRuleServices(services || null),
  });
  users.audit({ kind: "firewall.add_manual", ip, label });
  res.json({ success: true, message: tr(req, "firewall.allowed", { ip }) });
}));

app.post("/api/firewall/remove", firewallLimiter, asyncH(async (req, res) => {
  const { ip } = req.body;
  if (!ip || !firewall.isValidPublicIPv4(ip)) {
    return res.status(400).json({ success: false, error: tr(req, "error.invalid_ip") });
  }
  const rule = firewall.findRuleByIp(ip);
  if (!rule) return res.status(404).json({ success: false, error: tr(req, "error.ip_not_found") });
  await firewall.ufwDeleteMany(ip, firewall.flattenPorts(rule));
  firewall.deleteRuleByIp(ip);
  users.audit({ kind: "firewall.remove_manual", ip });
  res.json({ success: true, message: tr(req, "firewall.removed", { ip }) });
}));

// ---------------------------------------------------------------------------
// Active sessions + stats
// ---------------------------------------------------------------------------

app.get("/api/active-sessions", asyncH(async (req, res) => {
  const fwData = firewall.loadRules();
  const allUsers = users.listUsers();
  const allPorts = registry.collectPorts();
  const conns = await connections.listAllConnections(allPorts);
  const liveByIp = new Map();
  for (const c of conns) {
    if (!liveByIp.has(c.srcIp)) liveByIp.set(c.srcIp, new Set());
    liveByIp.get(c.srcIp).add(`${c.dstPort}/${c.proto}`);
  }
  // Try RCON /list per service to enrich with player names
  const playersByService = {};
  for (const adapter of registry.services.values()) {
    if (adapter.hasCapability && adapter.hasCapability("rcon") && adapter.isRconConnected && adapter.isRconConnected()) {
      try {
        const r = await adapter.rconSend("list");
        const m = r.match(/There are \d+ of a max of \d+ players online:(.*)/);
        if (m) playersByService[adapter.id] = m[1].split(",").map((p) => p.trim()).filter(Boolean);
      } catch {
        // ignore
      }
    }
  }

  const sessions = [];
  for (const u of allUsers) {
    const rule = fwData.rules.find((r) => r.userId === u.id);
    const ip = rule ? rule.ip : null;
    const liveSet = ip ? (liveByIp.get(ip) || new Set()) : new Set();
    const services = (u.allowedServices || []).map((sid) => {
      const adapter = registry.get(sid);
      const ports = adapter ? adapter.ports : [];
      const connected = ports.some((p) => liveSet.has(`${p.port}/${p.proto}`));
      return {
        id: sid,
        name: adapter ? adapter.name : sid,
        connected,
        playerNames: playersByService[sid] || [],
      };
    });
    sessions.push({
      userId: u.id,
      name: u.name,
      ip,
      ipExpiresAt: rule ? rule.expiresAt : null,
      services,
    });
  }
  res.json({ success: true, sessions });
}));

app.get("/api/stats", (req, res) => {
  res.json({
    success: true,
    stats: stats.loadStats(),
    leaderboard: stats.leaderboard(),
  });
});

// ---------------------------------------------------------------------------
// Users (admin CRUD)
// ---------------------------------------------------------------------------

app.get("/api/users", (req, res) => {
  res.json({ success: true, users: users.listUsersWithTokens() });
});

app.post("/api/users", asyncH(async (req, res) => {
  const { name, allowedServices, locale } = req.body;
  const u = users.createUser({ name, allowedServices, locale });
  res.json({ success: true, user: u });
}));

app.put("/api/users/:id", asyncH(async (req, res) => {
  const u = users.updateUser(req.params.id, req.body);
  res.json({ success: true, user: u });
}));

app.delete("/api/users/:id", asyncH(async (req, res) => {
  users.deleteUser(req.params.id);
  res.json({ success: true });
}));

app.post("/api/users/:id/rotate-token", asyncH(async (req, res) => {
  const token = users.rotateToken(req.params.id);
  res.json({ success: true, token });
}));

app.post("/api/users/:id/revoke", asyncH(async (req, res) => {
  const r = await users.revokeUser(req.params.id);
  res.json({ success: true, ...r });
}));

// ---------------------------------------------------------------------------
// Per-user knock + PWA endpoints
// ---------------------------------------------------------------------------

const knockLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: "Too many requests" },
});

function userFromToken(req, res) {
  const u = users.findByToken(req.params.token);
  if (!u) {
    res.status(404).json({ success: false, error: tr(req, "error.invalid_token") });
    return null;
  }
  return u;
}

// Personal PWA — server-rendered HTML with i18n + absolute asset URLs inlined
app.get("/u/:token", (req, res) => {
  const u = users.findByToken(req.params.token);
  if (!u) {
    return res
      .status(404)
      .type("html")
      .send("<!doctype html><meta charset=utf-8><title>Not found</title><h1>Invalid link</h1>");
  }
  const l = lang(req, u);
  const dict = i18n.getDictForClient(l);
  const services = (u.allowedServices || []).map((id) => {
    const a = registry.get(id);
    return a ? { id, name: a.name } : { id, name: id };
  });
  const initial = {
    user: { id: u.id, name: u.name },
    services,
    token: u.token,
    lang: l,
  };
  const html = renderUserPwa({ initial, dict, lang: l, token: u.token });
  res.type("html").send(html);
});

app.get("/u/:token/state", (req, res) => {
  const u = userFromToken(req, res); if (!u) return;
  const rule = firewall.findRuleByUserId(u.id);
  const services = (u.allowedServices || []).map((id) => {
    const a = registry.get(id);
    return a ? { id, name: a.name } : { id, name: id };
  });
  res.json({
    success: true,
    user: { id: u.id, name: u.name },
    services,
    active: rule
      ? { ip: rule.ip, expiresAt: rule.expiresAt, services: (rule.services || []).map((s) => s.id) }
      : null,
  });
});

app.post("/u/:token/knock", knockLimiter, asyncH(async (req, res) => {
  const u = userFromToken(req, res); if (!u) return;
  const ip = clientIp(req);
  const force = req.query.force === "true" || req.body?.force === true;
  const requested = req.body?.services || req.query.services || "all";
  const requestedArr =
    requested === "all"
      ? "all"
      : Array.isArray(requested)
        ? requested
        : String(requested).split(",").map((s) => s.trim()).filter(Boolean);
  if (isIgnoredRange(ip)) {
    return res.status(400).json({ success: false, error: "IP in ignored range" });
  }
  try {
    const result = await users.knockUser(u, ip, requestedArr, {
      registry,
      force,
      ua: req.headers["user-agent"] || null,
    });
    if (result.requireConfirm) {
      return res.status(409).json({ success: false, ...result });
    }
    res.json({
      success: true,
      ip,
      expiresAt: result.expiresAt,
      services: (result.rule.services || []).map((s) => s.id),
    });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
}));

app.post("/u/:token/revoke", asyncH(async (req, res) => {
  const u = userFromToken(req, res); if (!u) return;
  const r = await users.revokeUser(u.id);
  res.json({ success: true, ...r });
}));

app.get("/u/:token/stats", (req, res) => {
  const u = userFromToken(req, res); if (!u) return;
  res.json({ success: true, stats: stats.summarizeUser(u.id) });
});

// ---------------------------------------------------------------------------
// PWA HTML rendering (inline so no extra fetch is needed)
// ---------------------------------------------------------------------------

let cachedPwaTemplate = null;
function renderUserPwa({ initial, dict, lang: l, token }) {
  if (!cachedPwaTemplate) {
    try {
      cachedPwaTemplate = fs.readFileSync(path.join(__dirname, "pwa", "index.html"), "utf8");
    } catch (err) {
      console.error("PWA template missing:", err.message);
      cachedPwaTemplate = "<!doctype html><h1>PWA template missing</h1>";
    }
  }
  const base = `/u/${token}`;
  return cachedPwaTemplate
    .replace(/\{\{LANG\}\}/g, l)
    .replace(/\{\{BASE\}\}/g, base)
    .replace(
      /\{\{INIT\}\}/g,
      `<script>window.__I18N__=${JSON.stringify(dict)};window.__INIT__=${JSON.stringify(initial)};</script>`,
    );
}

// PWA static assets
app.get("/u/:token/manifest.json", (req, res) => {
  res.json({
    name: "Game Knock",
    short_name: "Play",
    start_url: `/u/${req.params.token}`,
    scope: `/u/${req.params.token}`,
    display: "standalone",
    background_color: "#1a1a2e",
    theme_color: "#1a1a2e",
    icons: [
      {
        src:
          "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 192 192'%3E%3Crect fill='%232d6a4f' width='192' height='192' rx='28'/%3E%3Ctext x='96' y='128' text-anchor='middle' font-size='96' font-family='sans-serif' fill='white'%3E%E2%9C%93%3C/text%3E%3C/svg%3E",
        sizes: "192x192 512x512",
        type: "image/svg+xml",
        purpose: "any maskable",
      },
    ],
  });
});

app.get("/u/:token/sw.js", (req, res) => {
  res.type("application/javascript").sendFile(path.join(__dirname, "pwa", "sw.js"));
});

app.get("/u/:token/u.js", (req, res) => {
  res.type("application/javascript").sendFile(path.join(__dirname, "pwa", "u.js"));
});

app.get("/u/:token/u.css", (req, res) => {
  res.type("text/css").sendFile(path.join(__dirname, "pwa", "u.css"));
});

// ---------------------------------------------------------------------------
// Auto-expire sweeper (every 10 min)
// ---------------------------------------------------------------------------

setInterval(() => {
  users.sweepExpiredRules().catch((err) => console.error("sweep error:", err.message));
}, 10 * 60 * 1000);

// Stats collector
stats.start(registry);

// ---------------------------------------------------------------------------
// BlueMap knock-proxy (legacy, optional) — kept on its own port
// ---------------------------------------------------------------------------

if (BLUEMAP_HOST) {
  const knockApp = express();
  // Note: this legacy proxy still does the old "anonymous knock = allow"
  // dance for backwards compatibility with people who set KNOCK_AUTO_APPROVE.
  // The recommended new flow is per-user /u/:token PWA which has smart-revoke.
  knockApp.use((req, _res, next) => {
    const ip = clientIp(req);
    if (firewall.isValidPublicIPv4(ip) && !isIgnoredRange(ip)) {
      // Legacy auto-approve: open default service ports
      if (process.env.KNOCK_AUTO_APPROVE === "true") {
        const ports = registry.collectPorts([DEFAULT_SERVICE_ID]);
        firewall.ufwAllowMany(ip, ports).catch((err) =>
          console.error("legacy knock allow failed:", err.message),
        );
        const existing = firewall.findRuleByIp(ip);
        if (!existing) {
          firewall.upsertRule({
            ip,
            addedAt: new Date().toISOString(),
            label: "Auto-approved (legacy bluemap)",
            services: registry.buildRuleServices([DEFAULT_SERVICE_ID]),
          });
        }
      }
    }
    next();
  });
  knockApp.use(
    createProxyMiddleware({
      target: `http://${BLUEMAP_HOST}`,
      changeOrigin: true,
      ws: true,
    }),
  );
  knockApp.listen(KNOCK_PORT, () => {
    console.log(`BlueMap knock-proxy on port ${KNOCK_PORT} → ${BLUEMAP_HOST}`);
  });
} else {
  console.log("BLUEMAP_HOST not set - BlueMap knock-proxy disabled");
}

// ---------------------------------------------------------------------------

app.listen(API_PORT, () => {
  console.log(`Multi-game dashboard API running on port ${API_PORT}`);
  console.log(`  default service: ${DEFAULT_SERVICE_ID}`);
  console.log(`  configured services: ${registry.list().map((s) => s.id).join(", ")}`);
  console.log(`  default locale: ${i18n.DEFAULT_LOCALE}`);
});
