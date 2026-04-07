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

loadI18n();
loadServices();

async function api(path, opts) {
  try {
    const res = await fetch(`${API}${path}`, opts);
    return await res.json();
  } catch (err) {
    toast(err.message, "error");
    return null;
  }
}

// --- Status polling ---
async function refreshStatus() {
  const [status, rcon] = await Promise.all([
    api("/api/status"),
    api("/api/rcon-status"),
  ]);

  if (status) {
    const badge = document.getElementById("status-badge");
    const isOnline = status.status === "started";
    badge.textContent = isOnline ? "Online" : "Offline";
    badge.className = `badge ${isOnline ? "badge-online" : "badge-offline"}`;

    document.getElementById("server-status").textContent = isOnline
      ? "Running"
      : "Stopped";
    document.getElementById("player-count").textContent = status.online;

    const list = document.getElementById("player-list");
    list.innerHTML = status.players
      .map((p) => `<span class="player-tag">${p}</span>`)
      .join("");

    // Update current world from status (no extra request needed)
    if (status.currentWorld) {
      document.getElementById("current-world").textContent = status.currentWorld;
    }
  }

  if (rcon) {
    document.getElementById("rcon-status").textContent = rcon.connected
      ? "Connected"
      : "Disconnected";
  }
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
    loadKnocks();
    loadAttempts();
  }
}

let pollTimer = setInterval(poll, 10000);
refreshStatus();

// Pause polling when tab is hidden, resume when visible
document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    clearInterval(pollTimer);
    pollTimer = null;
  } else {
    refreshStatus();
    loadWorlds();
    listBackups();
    loadFirewallRules();
    loadKnocks();
    loadAttempts();
    pollTimer = setInterval(poll, 10000);
    pollCount = 0;
  }
});

// --- Server actions ---
async function serverAction(action) {
  const data = await api(`/api/${action}`);
  if (data) toast(data.message || data.error || "OK");
}

// --- Gamemode ---
async function setGamemode(mode) {
  const data = await api(`/api/gamemode-all/${mode}`);
  if (data) toast(data.message || data.error || "OK");
}

// --- RCON command ---
async function sendCommand() {
  const input = document.getElementById("rcon-cmd");
  const cmd = input.value.trim();
  if (!cmd) return;

  const data = await api(`/api/command/${encodeURIComponent(cmd)}`);
  const output = document.getElementById("cmd-output");
  if (data) {
    output.textContent = data.response || data.error || JSON.stringify(data);
    output.classList.add("visible");
  }
  input.value = "";
}

// --- Whitelist ---
async function whitelistAction(action) {
  const player = document.getElementById("whitelist-player").value.trim();
  if (!player) return toast("Enter a player name", "error");

  const data = await api(`/api/whitelist/${action}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ player }),
  });
  if (data) toast(data.response || data.error || "OK");
}

async function showWhitelist() {
  const data = await api("/api/whitelist");
  const output = document.getElementById("whitelist-output");
  if (data) {
    output.textContent = data.response || "No data";
    output.classList.add("visible");
  }
}

// --- OP ---
async function opAction(action) {
  const player = document.getElementById("op-player").value.trim();
  if (!player) return toast("Enter a player name", "error");

  const data = await api(`/api/${action}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ player }),
  });
  if (data) toast(data.response || data.error || "OK");
}

// --- Worlds ---
async function loadWorlds() {
  const data = await api("/api/list-worlds");
  if (!data) return;

  document.getElementById("current-world").textContent = data.currentWorld || "unknown";

  const list = document.getElementById("world-list");
  if (data.worlds && data.worlds.length) {
    list.innerHTML = data.worlds
      .map(
        (w) =>
          `<li class="world-item ${w === data.currentWorld ? "world-active" : ""}">
            <span>${w}${w === data.currentWorld ? " (active)" : ""}</span>
            ${
              w !== data.currentWorld
                ? `<button onclick="switchWorld('${w}')" class="btn btn-sm btn-green">Load</button>`
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
  const data = await api("/api/save-current");
  if (data) {
    toast(data.message || data.error || "OK");
    loadWorlds();
  }
}

async function switchWorld(name) {
  if (!confirm(`Switch to world "${name}"? Server will restart.`)) return;
  const data = await api(`/api/change-world/${encodeURIComponent(name)}`);
  if (data) toast(data.message || data.error || "OK");
}

async function createNewWorld() {
  const input = document.getElementById("new-world-name");
  const name = input.value.trim();
  if (!name) return toast("Enter a world name", "error");
  if (!confirm(`Generate new world "${name}"? Server will restart.`)) return;

  const data = await api(`/api/new-world/${encodeURIComponent(name)}`);
  if (data) toast(data.message || data.error || "OK");
  input.value = "";
}

async function uploadWorld() {
  const fileInput = document.getElementById("world-file");
  if (!fileInput.files.length) return toast("Select a .zip file first", "error");

  const formData = new FormData();
  formData.append("worldFile", fileInput.files[0]);

  toast("Uploading world...");
  const data = await api("/api/upload-world", { method: "POST", body: formData });
  if (data) {
    toast(data.message || data.error || "OK", data.success ? "success" : "error");
    fileInput.value = "";
    loadWorlds();
  }
}

loadWorlds();

// --- Backups ---
async function listBackups() {
  const data = await api("/api/list-backups");
  const list = document.getElementById("backup-list");
  if (data && data.backups) {
    list.innerHTML = data.backups.length
      ? data.backups
          .map(
            (b) =>
              `<li class="backup-item">
                <span>${b}</span>
                <button onclick="restoreBackup('${b}')" class="btn btn-sm btn-blue">Restore</button>
              </li>`
          )
          .join("")
      : "<li>No backups found</li>";
  }
}

async function restoreBackup(name) {
  if (!confirm(`Restore backup "${name}"? Server will restart.`)) return;
  const data = await api(`/api/restore-backup/${encodeURIComponent(name)}`);
  if (data) toast(data.message || data.error || "OK");
}

listBackups();

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
  const services = [
    "https://api.ipify.org?format=json",
    "https://api64.ipify.org?format=json",
    "https://jsonip.com",
  ];
  for (const url of services) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5000);
      const res = await fetch(url, { signal: controller.signal });
      clearTimeout(timer);
      const data = await res.json();
      if (data.ip) return data.ip;
    } catch { /* try next */ }
  }
  return null;
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

loadFirewallRules();

// --- Pending Knocks ---
function timeAgo(isoString) {
  const diff = Date.now() - new Date(isoString).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins} min ago`;
  const hrs = Math.floor(mins / 60);
  return `${hrs}h ${mins % 60}m ago`;
}

async function loadKnocks() {
  const data = await api("/api/firewall/knocks");
  const list = document.getElementById("knocks-list");
  if (!data) {
    list.innerHTML = "<li>Failed to load knocks</li>";
  } else if (data.knocks && data.knocks.length) {
    list.innerHTML = data.knocks
      .map(
        (k) =>
          `<li class="firewall-item">
            <span>
              <span class="firewall-ip">${escapeHtml(k.ip)}</span>
              <span class="firewall-meta">${escapeHtml(k.country)}${k.countryCode ? ` (${escapeHtml(k.countryCode)})` : ""} &middot; ${timeAgo(k.timestamp)}</span>
            </span>
            <span>
              <button onclick="approveKnock('${escapeHtml(k.ip)}')" class="btn btn-sm btn-green">Approve</button>
              <button onclick="dismissKnock('${escapeHtml(k.ip)}')" class="btn btn-sm btn-red">Dismiss</button>
            </span>
          </li>`
      )
      .join("");
  } else {
    list.innerHTML = "<li>No pending knocks</li>";
  }
}

async function approveKnock(ip) {
  const label = prompt(`Label for ${ip} (optional):`, "");
  if (label === null) return;
  const data = await api("/api/firewall/knocks/approve", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip, label }),
  });
  if (data) {
    toast(data.message || data.error || "OK", data.success ? "success" : "error");
    loadKnocks();
    loadFirewallRules();
  }
}

async function dismissKnock(ip) {
  if (!confirm(`Dismiss knock from ${ip}?`)) return;
  const data = await api("/api/firewall/knocks/dismiss", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip }),
  });
  if (data) {
    toast(data.message || data.error || "OK", data.success ? "success" : "error");
    loadKnocks();
  }
}

loadKnocks();

// --- Connection Attempts ---
async function loadAttempts() {
  const data = await api("/api/firewall/attempts");
  const list = document.getElementById("attempts-list");
  if (!data) {
    list.innerHTML = "<li>Failed to load attempts</li>";
  } else if (data.error) {
    list.innerHTML = `<li>Error: ${escapeHtml(data.error)}</li>`;
  } else if (data.attempts) {
    list.innerHTML = data.attempts.length
      ? data.attempts
          .map(
            (a) =>
              `<li class="firewall-item">
                <span>
                  <span class="firewall-ip">${escapeHtml(a.ip)}</span>
                  <span class="firewall-meta">${escapeHtml(a.country)}${a.countryCode ? ` (${escapeHtml(a.countryCode)})` : ""} &middot; ${a.count} attempt${a.count !== 1 ? "s" : ""} &middot; ports ${a.ports.join(", ")}</span>
                </span>
                <button onclick="allowAttemptIp('${escapeHtml(a.ip)}')" class="btn btn-sm btn-green">Allow</button>
              </li>`
          )
          .join("")
      : "<li>No blocked attempts in the last 5 minutes</li>";
  }
}

async function allowAttemptIp(ip) {
  const label = prompt(`Label for ${ip} (optional):`, "");
  if (label === null) return; // cancelled
  const data = await api("/api/firewall/add", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip, label }),
  });
  if (data) {
    toast(data.message || data.error || "OK", data.success ? "success" : "error");
    loadFirewallRules();
    loadAttempts();
  }
}

loadAttempts();

// --- Logs ---
async function loadLogs() {
  const data = await api("/api/logs?lines=100");
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

loadUsers();
loadActiveSessions();
loadStatsLeaderboard();
