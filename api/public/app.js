const API = window.location.origin;

// ---- i18n -----------------------------------------------------------------
let I18N = {};
let CURRENT_LANG = "en";

async function loadI18n() {
  try {
    const res = await fetch("/api/i18n");
    const data = await res.json();
    I18N = data.dict || {};
    CURRENT_LANG = data.lang || "en";
    document.documentElement.lang = CURRENT_LANG;
    applyI18n();
  } catch (err) {
    console.error("i18n load failed:", err);
  }
}

// ---- Auth overlay (Phase 1) -----------------------------------------------
const $ = (id) => document.getElementById(id);

function showAuth() { $("auth-overlay").classList.remove("hidden"); $("app").classList.add("hidden"); }
function hideAuth() { $("auth-overlay").classList.add("hidden"); $("app").classList.remove("hidden"); }
function authMsg(text, kind = "") { const el = $("auth-msg"); el.textContent = text || ""; el.className = "auth-msg" + (kind ? " " + kind : ""); }

async function checkSessionOrLogin() {
  try {
    const r = await fetch("/api/admin/me", { credentials: "same-origin" });
    if (r.ok) {
      hideAuth();
      bootApp();
      return;
    }
  } catch (err) {
    console.error("session check failed", err);
  }
  // Not logged in → inspect bootstrap state.
  showAuth();
  let bootstrap = null;
  try {
    const r = await fetch("/api/admin/bootstrap");
    bootstrap = await r.json();
  } catch (err) {
    authMsg("Unable to reach server", "error");
    return;
  }
  if (bootstrap && bootstrap.open) {
    $("auth-bootstrap").classList.remove("hidden");
    $("auth-login").classList.add("hidden");
    $("auth-locked").classList.add("hidden");
    $("auth-bootstrap-remaining").textContent =
      `Window closes in ~${bootstrap.minutesRemaining} min.`;
    authMsg("");
    return;
  }
  // Window closed → either there IS an admin (show login) or we can't
  // tell the difference from the client side, so try login first.
  $("auth-bootstrap").classList.add("hidden");
  $("auth-login").classList.remove("hidden");
  $("auth-locked").classList.add("hidden");
  authMsg("");
}

async function authStartBootstrap() {
  const name = $("auth-bootstrap-name").value.trim();
  if (!name) { authMsg("Enter a name first", "error"); return; }
  authMsg("Creating admin…");
  let adminId;
  try {
    const r = await fetch("/api/admin/bootstrap/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ name }),
    });
    const data = await r.json();
    if (!r.ok || !data.success) throw new Error(data.error || "failed");
    adminId = data.adminId;
  } catch (err) {
    authMsg("Bootstrap failed: " + err.message, "error");
    return;
  }
  authMsg("Touch your authenticator to register the passkey…");
  try {
    const optsRes = await fetch("/api/admin/webauthn/register/options", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ adminId }),
    });
    const optsData = await optsRes.json();
    if (!optsRes.ok || !optsData.success) throw new Error(optsData.error || "no options");
    const att = await window.webauthnRegister(optsData.options);
    const verifyRes = await fetch("/api/admin/webauthn/register/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ adminId, response: att, deviceLabel: navigator.userAgent.slice(0, 60) }),
    });
    const verifyData = await verifyRes.json();
    if (!verifyRes.ok || !verifyData.success) throw new Error(verifyData.error || "verify failed");
    authMsg("Registered! Entering dashboard…");
    hideAuth();
    bootApp();
  } catch (err) {
    authMsg("Registration failed: " + (err.message || err), "error");
  }
}

async function authLogin() {
  authMsg("Touch your authenticator…");
  try {
    const optsRes = await fetch("/api/admin/webauthn/authenticate/options", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
    });
    const optsData = await optsRes.json();
    if (!optsRes.ok || !optsData.success) throw new Error(optsData.error || "no options");
    const assertion = await window.webauthnAuthenticate(optsData.options);
    const verifyRes = await fetch("/api/admin/webauthn/authenticate/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ response: assertion }),
    });
    const verifyData = await verifyRes.json();
    if (!verifyRes.ok || !verifyData.success) throw new Error(verifyData.error || "login failed");
    authMsg("Welcome!");
    hideAuth();
    bootApp();
  } catch (err) {
    authMsg("Login failed: " + (err.message || err), "error");
  }
}

async function authLogout() {
  try {
    await fetch("/api/admin/logout", { method: "POST", credentials: "same-origin" });
  } catch { /* ignore */ }
  window.location.reload();
}

function t(key, vars) {
  let s = I18N[key] || key;
  if (vars) {
    for (const [k, v] of Object.entries(vars)) {
      s = s.replace(new RegExp(`\\{${k}\\}`, "g"), String(v));
    }
  }
  return s;
}

function applyI18n() {
  for (const el of document.querySelectorAll("[data-i18n]")) {
    el.textContent = t(el.dataset.i18n);
  }
  for (const el of document.querySelectorAll("[data-i18n-placeholder]")) {
    el.placeholder = t(el.dataset.i18nPlaceholder);
  }
}

// ---- Services registry + selector ----------------------------------------
let SERVICES = [];
let CURRENT_SERVICE = null;

async function loadServices() {
  try {
    const res = await fetch("/api/services");
    const data = await res.json();
    SERVICES = data.services || [];
    CURRENT_SERVICE = data.defaultId || (SERVICES[0] && SERVICES[0].id);
    const sel = document.getElementById("service-select");
    if (sel) {
      sel.innerHTML = SERVICES.map(
        (s) => `<option value="${s.id}">${escapeHtml(s.name)}</option>`,
      ).join("");
      sel.value = CURRENT_SERVICE;
      sel.onchange = () => {
        CURRENT_SERVICE = sel.value;
        refreshStatus();
      };
    }
  } catch (err) {
    console.error("services load failed:", err);
  }
}

function toast(msg, type = "success") {
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.className = `toast show ${type}`;
  setTimeout(() => (el.className = "toast"), 3000);
}

async function api(path, opts) {
  try {
    const mergedOpts = Object.assign({ credentials: "same-origin" }, opts || {});
    const res = await fetch(`${API}${path}`, mergedOpts);
    if (res.status === 401) {
      showAuth();
      checkSessionOrLogin();
      return null;
    }
    return await res.json();
  } catch (err) {
    toast(err.message, "error");
    return null;
  }
}

// --- Status polling ---
async function refreshStatus() {
  if (!CURRENT_SERVICE) return;
  const status = await api(`/api/services/${CURRENT_SERVICE}/status`);
  if (!status || !status.success) return;
  const badge = document.getElementById("status-badge");
  const isOnline = !!status.running;
  badge.textContent = isOnline ? "Online" : "Offline";
  badge.className = `badge ${isOnline ? "badge-online" : "badge-offline"}`;

  document.getElementById("server-status").textContent = isOnline
    ? "Running"
    : "Stopped";
  document.getElementById("player-count").textContent = (status.players || []).length;

  const list = document.getElementById("player-list");
  list.innerHTML = (status.players || [])
    .map((p) => `<span class="player-tag">${escapeHtml(p)}</span>`)
    .join("");

  const details = status.details || {};
  if (details.currentWorld) {
    document.getElementById("current-world").textContent = details.currentWorld;
  }
  document.getElementById("rcon-status").textContent =
    details.rconConnected ? "Connected" : "Disconnected";
}

// Slow-poll worlds and backups (every 30s)
let pollCount = 0;
function poll() {
  refreshStatus();
  pollCount++;
  if (pollCount % 3 === 0) {
    loadWorlds();
    listBackups();
    loadFirewallRules();
  }
}

let pollTimer = null;

function startPolling() {
  if (pollTimer) return;
  pollTimer = setInterval(poll, 10000);
}
function stopPolling() {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
}

// Pause polling when tab is hidden, resume when visible
document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    stopPolling();
  } else if (!$("app").classList.contains("hidden")) {
    refreshStatus();
    loadWorlds();
    listBackups();
    loadFirewallRules();
    startPolling();
    pollCount = 0;
  }
});

// --- Server actions ---
async function serverAction(action) {
  if (!CURRENT_SERVICE) return;
  // Map the old dashboard button names to the new service-keyed routes.
  const map = {
    start: { path: "start", method: "POST" },
    stop: { path: "stop", method: "POST" },
    restart: { path: "restart", method: "POST" },
    backup: { path: "backup", method: "POST" },
  };
  const route = map[action];
  if (!route) return;
  const data = await api(`/api/services/${CURRENT_SERVICE}/${route.path}`, {
    method: route.method,
  });
  if (data) toast(data.message || data.error || "OK");
}

// --- Gamemode (sent via the whitelisted RCON /command route) ---
async function setGamemode(mode) {
  if (!CURRENT_SERVICE) return;
  const data = await api(
    `/api/services/${CURRENT_SERVICE}/command/${encodeURIComponent("gamemode " + mode + " @a")}`,
  );
  if (data) toast(data.response || data.error || "OK");
}

// --- RCON command ---
async function sendCommand() {
  if (!CURRENT_SERVICE) return;
  const input = document.getElementById("rcon-cmd");
  const cmd = input.value.trim();
  if (!cmd) return;
  const data = await api(
    `/api/services/${CURRENT_SERVICE}/command/${encodeURIComponent(cmd)}`,
  );
  const output = document.getElementById("cmd-output");
  if (data) {
    output.textContent = data.response || data.error || JSON.stringify(data);
    output.classList.add("visible");
  }
  input.value = "";
}

// --- Whitelist ---
async function whitelistAction(action) {
  if (!CURRENT_SERVICE) return;
  const player = document.getElementById("whitelist-player").value.trim();
  if (!player) return toast("Enter a player name", "error");
  const data = await api(`/api/services/${CURRENT_SERVICE}/whitelist/${action}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ player }),
  });
  if (data) toast(data.response || data.error || "OK");
}

async function showWhitelist() {
  if (!CURRENT_SERVICE) return;
  const data = await api(`/api/services/${CURRENT_SERVICE}/whitelist`);
  const output = document.getElementById("whitelist-output");
  if (data) {
    output.textContent = data.response || "No data";
    output.classList.add("visible");
  }
}

// --- OP ---
async function opAction(action) {
  if (!CURRENT_SERVICE) return;
  const player = document.getElementById("op-player").value.trim();
  if (!player) return toast("Enter a player name", "error");
  const data = await api(`/api/services/${CURRENT_SERVICE}/${action}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ player }),
  });
  if (data) toast(data.response || data.error || "OK");
}

// --- Worlds ---
async function loadWorlds() {
  if (!CURRENT_SERVICE) return;
  const data = await api(`/api/services/${CURRENT_SERVICE}/worlds`);
  if (!data || !data.success) return;

  document.getElementById("current-world").textContent = data.currentWorld || "unknown";

  const list = document.getElementById("world-list");
  if (data.worlds && data.worlds.length) {
    list.innerHTML = data.worlds
      .map(
        (w) =>
          `<li class="world-item ${w === data.currentWorld ? "world-active" : ""}">
            <span>${escapeHtml(w)}${w === data.currentWorld ? " (active)" : ""}</span>
            ${
              w !== data.currentWorld
                ? `<button onclick="switchWorld('${escapeAttr(w)}')" class="btn btn-sm btn-green">Load</button>`
                : ""
            }
          </li>`
      )
      .join("");
  } else {
    list.innerHTML = "<li>No saved worlds</li>";
  }
}

async function saveCurrentWorld() {
  if (!CURRENT_SERVICE) return;
  const data = await api(`/api/services/${CURRENT_SERVICE}/worlds/save-current`, {
    method: "POST",
  });
  if (data) {
    toast(data.message || data.error || "OK");
    loadWorlds();
  }
}

async function switchWorld(name) {
  if (!CURRENT_SERVICE) return;
  if (!confirm(`Switch to world "${name}"? Server will restart.`)) return;
  const data = await api(
    `/api/services/${CURRENT_SERVICE}/worlds/${encodeURIComponent(name)}/switch`,
    { method: "POST" },
  );
  if (data) toast(data.message || data.error || "OK");
}

async function createNewWorld() {
  if (!CURRENT_SERVICE) return;
  const input = document.getElementById("new-world-name");
  const name = input.value.trim();
  if (!name) return toast("Enter a world name", "error");
  if (!confirm(`Generate new world "${name}"? Server will restart.`)) return;
  const data = await api(
    `/api/services/${CURRENT_SERVICE}/worlds/${encodeURIComponent(name)}/new`,
    { method: "POST" },
  );
  if (data) toast(data.message || data.error || "OK");
  input.value = "";
}

// World upload is deferred until the per-service adapter accepts the
// stream into its own worlds directory. Left as a no-op so the existing
// button doesn't look broken.
async function uploadWorld() {
  toast("World upload is temporarily disabled", "error");
}

// --- Backups ---
async function listBackups() {
  if (!CURRENT_SERVICE) return;
  const data = await api(`/api/services/${CURRENT_SERVICE}/backups`);
  const list = document.getElementById("backup-list");
  if (data && data.backups) {
    list.innerHTML = data.backups.length
      ? data.backups
          .map(
            (b) =>
              `<li class="backup-item">
                <span>${escapeHtml(b)}</span>
                <button onclick="restoreBackup('${escapeAttr(b)}')" class="btn btn-sm btn-blue">Restore</button>
              </li>`
          )
          .join("")
      : "<li>No backups found</li>";
  }
}

async function restoreBackup(name) {
  if (!CURRENT_SERVICE) return;
  if (!confirm(`Restore backup "${name}"? Server will restart.`)) return;
  const data = await api(
    `/api/services/${CURRENT_SERVICE}/backups/${encodeURIComponent(name)}/restore`,
    { method: "POST" },
  );
  if (data) toast(data.message || data.error || "OK");
}

// --- Firewall ---
async function loadFirewallRules() {
  const data = await api("/api/firewall");
  const list = document.getElementById("firewall-list");
  if (data && data.rules) {
    list.innerHTML = data.rules.length
      ? data.rules
          .map(
            (r) => {
              let meta = escapeHtml(r.label || "");
              if (r.expiresAt) {
                const remaining = new Date(r.expiresAt).getTime() - Date.now();
                const hrs = Math.floor(remaining / 3600000);
                const mins = Math.floor((remaining % 3600000) / 60000);
                meta += ` · expires in ${hrs}h ${mins}m`;
              }
              return `<li class="firewall-item">
                <span>
                  <span class="firewall-ip">${escapeHtml(r.ip)}</span>
                  <span class="firewall-meta">${meta}</span>
                </span>
                <button onclick="removeFirewallIp('${escapeHtml(r.ip)}')" class="btn btn-sm btn-red">Remove</button>
              </li>`;
            }
          )
          .join("")
      : "<li>No IPs allowed</li>";
  }
}

function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

async function detectPublicIp() {
  // Ask the server — it already knows req.ip from trust-proxy and falls
  // back to an upstream lookup if needed. This replaces the direct call
  // to ipify / jsonip that used to leak the admin's browser to third
  // parties.
  const data = await api("/api/public-ip");
  return data && data.success ? data.ip : null;
}

async function allowMyIp() {
  toast("Detecting your public IP...");
  const ip = await detectPublicIp();
  if (!ip) return toast("Could not detect your public IP. Use manual input instead.", "error");
  if (!confirm(`Allow your public IP ${ip}?`)) return;
  const data = await api("/api/firewall/add", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip, label: "My IP" }),
  });
  if (data) {
    toast(data.message || data.error || "OK", data.success ? "success" : "error");
    loadFirewallRules();
  }
}

async function addFirewallIp() {
  const ip = document.getElementById("firewall-ip").value.trim();
  const label = document.getElementById("firewall-label").value.trim();
  if (!ip) return toast("Enter an IP address", "error");
  const data = await api("/api/firewall/add", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip, label }),
  });
  if (data) {
    toast(data.message || data.error || "OK", data.success ? "success" : "error");
    if (data.success) {
      document.getElementById("firewall-ip").value = "";
      document.getElementById("firewall-label").value = "";
      loadFirewallRules();
    }
  }
}

async function removeFirewallIp(ip) {
  if (!confirm(`Remove ${ip} from firewall allowlist?`)) return;
  const data = await api("/api/firewall/remove", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip }),
  });
  if (data) {
    toast(data.message || data.error || "OK", data.success ? "success" : "error");
    loadFirewallRules();
  }
}

// --- Logs ---
async function loadLogs() {
  if (!CURRENT_SERVICE) return;
  const data = await api(`/api/services/${CURRENT_SERVICE}/logs?lines=100`);
  const output = document.getElementById("log-output");
  if (data && data.logs) {
    output.textContent = data.logs.join("\n");
    output.classList.add("visible");
    output.scrollTop = output.scrollHeight;
  }
}

// --- Users (per-child knock links) ---------------------------------------
async function loadUsers() {
  const data = await api("/api/users");
  const list = document.getElementById("user-list");
  if (!list) return;
  if (!data || !data.users || data.users.length === 0) {
    list.innerHTML = `<li class="muted">${t("users.no_users")}</li>`;
    return;
  }
  const origin = window.location.origin;
  list.innerHTML = data.users
    .map((u) => {
      const url = `${origin}/u/${u.token}`;
      const services = (u.allowedServices || []).join(", ") || "—";
      return `<li class="user-item">
        <div>
          <strong>${escapeHtml(u.name)}</strong>
          <div class="muted">${escapeHtml(services)}</div>
        </div>
        <div class="user-actions">
          <button class="btn btn-sm" onclick="copyKnockLink('${escapeAttr(url)}')">${t("btn.copy_link")}</button>
          <button class="btn btn-sm btn-red" onclick="deleteUser('${escapeAttr(u.id)}','${escapeAttr(u.name)}')">${t("common.delete")}</button>
        </div>
      </li>`;
    })
    .join("");
}

async function addUser() {
  const input = document.getElementById("user-name");
  const name = input.value.trim();
  if (!name) return toast(t("users.placeholder_name"), "error");
  // Default to all services so admin doesn't need a multi-select on first creation
  const allowedServices = SERVICES.map((s) => s.id);
  const data = await api("/api/users", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, allowedServices }),
  });
  if (data && data.success) {
    input.value = "";
    toast(t("users.created", { name }), "success");
    loadUsers();
  } else if (data) {
    toast(data.error || "Failed", "error");
  }
}

async function deleteUser(id, name) {
  if (!confirm(`${t("common.delete")} ${name}?`)) return;
  const data = await api(`/api/users/${id}`, { method: "DELETE" });
  if (data && data.success) {
    toast(t("users.deleted", { name }), "success");
    loadUsers();
  }
}

async function copyKnockLink(url) {
  try {
    await navigator.clipboard.writeText(url);
    toast(t("users.copy_link_done"), "success");
  } catch {
    prompt("Copy this link:", url);
  }
}

function escapeAttr(s) { return escapeHtml(s); }

// --- Directory (aggregated admins + knock users) -------------------------
function formatRelative(iso) {
  if (!iso) return t("directory.never");
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return iso;
  const diffSec = Math.max(0, Math.floor((Date.now() - then) / 1000));
  if (diffSec < 60) return t("directory.just_now");
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin} min`;
  const diffH = Math.floor(diffMin / 60);
  if (diffH < 24) return `${diffH} h`;
  const diffD = Math.floor(diffH / 24);
  if (diffD < 30) return `${diffD} d`;
  return new Date(iso).toLocaleDateString();
}

function directoryStatusCell(entry) {
  if (entry.kind === "admin") {
    if (!entry.credentials || entry.credentials.length === 0) {
      return `<span class="badge badge-warn">${t("directory.no_passkey")}</span>`;
    }
    return `<span class="badge badge-ok">${t("directory.active")}</span>`;
  }
  // knock user
  if (entry.registrationOpenUntil) {
    return `<span class="badge badge-warn">${t("directory.enroll_open")}</span>`;
  }
  if (!entry.credentials || entry.credentials.length === 0) {
    return `<span class="muted">${t("directory.token_only")}</span>`;
  }
  return `<span class="badge badge-ok">${t("directory.active")}</span>`;
}

async function loadDirectory() {
  const data = await api("/api/directory");
  const body = document.getElementById("directory-body");
  if (!body) return;
  if (!data || !data.entries || data.entries.length === 0) {
    body.innerHTML = `<tr><td colspan="5" class="muted">${t("directory.empty")}</td></tr>`;
    return;
  }
  body.innerHTML = data.entries
    .map((e) => {
      const roleLabel =
        e.role === "admin" ? t("directory.role_admin") : t("directory.role_child");
      const devices = (e.credentials || []).length;
      return `<tr>
        <td><strong>${escapeHtml(e.name)}</strong></td>
        <td>${escapeHtml(roleLabel)}</td>
        <td>${devices}</td>
        <td>${escapeHtml(formatRelative(e.lastSeenAt))}</td>
        <td>${directoryStatusCell(e)}</td>
      </tr>`;
    })
    .join("");
}

// --- Active sessions ------------------------------------------------------
async function loadActiveSessions() {
  const data = await api("/api/active-sessions");
  const list = document.getElementById("active-sessions-list");
  if (!list || !data || !data.sessions) return;
  if (data.sessions.length === 0) {
    list.innerHTML = `<li class="muted">${t("users.no_users")}</li>`;
    return;
  }
  list.innerHTML = data.sessions
    .map((s) => {
      const playing = s.services.find((sv) => sv.connected);
      let label;
      if (playing) {
        label = t("active.connected", { service: playing.name });
      } else if (s.ip) {
        label = t("active.idle_allowed");
      } else {
        label = t("active.idle_unallowed");
      }
      return `<li class="firewall-item">
        <span><strong>${escapeHtml(s.name)}</strong>
          <span class="firewall-meta">${escapeHtml(label)}${s.ip ? ` · ${escapeHtml(s.ip)}` : ""}</span>
        </span>
      </li>`;
    })
    .join("");
}

// --- Stats leaderboard ----------------------------------------------------
async function loadStatsLeaderboard() {
  const data = await api("/api/stats");
  const list = document.getElementById("stats-leaderboard");
  if (!list || !data || !data.leaderboard) return;
  if (data.leaderboard.length === 0) {
    list.innerHTML = `<li class="muted">${t("stats.no_data")}</li>`;
    return;
  }
  // Map userId → name via /api/users
  const usersData = await api("/api/users");
  const nameById = {};
  if (usersData && usersData.users) {
    for (const u of usersData.users) nameById[u.id] = u.name;
  }
  list.innerHTML = data.leaderboard
    .map((row) => {
      const h = Math.floor(row.totalSeconds / 3600);
      const m = Math.floor((row.totalSeconds % 3600) / 60);
      return `<li class="firewall-item">
        <span><strong>${escapeHtml(nameById[row.userId] || row.userId)}</strong></span>
        <span class="firewall-meta">${h}h ${m}m</span>
      </li>`;
    })
    .join("");
}

// ---- Dashboard boot (called after successful login) ---------------------
function bootApp() {
  loadServices();
  refreshStatus();
  loadWorlds();
  listBackups();
  loadFirewallRules();
  loadUsers();
  loadDirectory();
  loadActiveSessions();
  loadStatsLeaderboard();
  startPolling();
}

// ---- Entry point ---------------------------------------------------------
loadI18n();
checkSessionOrLogin();
