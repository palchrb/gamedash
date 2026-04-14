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
    const r = await fetch("/admin/api/admin/me", { credentials: "same-origin" });
    if (r.ok) {
      const me = await r.json();
      if (me.admin) CURRENT_ADMIN_ID = me.admin.id;
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
    const r = await fetch("/admin/api/admin/bootstrap");
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
    const r = await fetch("/admin/api/admin/bootstrap/start", {
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
    const optsRes = await fetch("/admin/api/admin/webauthn/register/options", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ adminId }),
    });
    const optsData = await optsRes.json();
    if (!optsRes.ok || !optsData.success) throw new Error(optsData.error || "no options");
    const att = await window.webauthnRegister(optsData.options);
    const verifyRes = await fetch("/admin/api/admin/webauthn/register/verify", {
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
    const optsRes = await fetch("/admin/api/admin/webauthn/authenticate/options", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
    });
    const optsData = await optsRes.json();
    if (!optsRes.ok || !optsData.success) throw new Error(optsData.error || "no options");
    const assertion = await window.webauthnAuthenticate(optsData.options);
    const verifyRes = await fetch("/admin/api/admin/webauthn/authenticate/verify", {
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
    await fetch("/admin/api/admin/logout", { method: "POST", credentials: "same-origin" });
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

// ---- Tab switching --------------------------------------------------------
let activeTab = "services";

function initTabs() {
  for (const btn of document.querySelectorAll(".tab")) {
    btn.addEventListener("click", () => {
      for (const b of document.querySelectorAll(".tab")) b.classList.remove("active");
      for (const c of document.querySelectorAll(".tab-content")) c.classList.remove("active");
      btn.classList.add("active");
      const tab = btn.dataset.tab;
      document.getElementById("tab-" + tab).classList.add("active");
      activeTab = tab;
      // Refresh management data when switching to that tab
      if (tab === "management") {
        loadUsers();
        loadDirectory();
        loadAdmins();
        loadActiveSessions();
        loadStatsLeaderboard();
      }
      if (tab === "play") {
        loadPlayerOverview();
      }
    });
  }
}

// ---- Capability gating ----------------------------------------------------
const CAP_CLASSES = ["rcon", "whitelist", "op", "backup", "worlds", "logs", "players"];

function updateCapabilityVisibility(capabilities) {
  for (const cap of CAP_CLASSES) {
    const show = capabilities.includes(cap);
    for (const el of document.querySelectorAll(".cap-" + cap)) {
      el.style.display = show ? "" : "none";
    }
  }
}

// ---- Services registry + selector ----------------------------------------
let SERVICES = [];
let SERVICE_MAP = {};
let CURRENT_SERVICE = null;

async function loadServices() {
  try {
    const res = await fetch("/admin/api/services");
    const data = await res.json();
    SERVICES = data.services || [];
    SERVICE_MAP = {};
    for (const s of SERVICES) SERVICE_MAP[s.id] = s;
    CURRENT_SERVICE = data.defaultId || (SERVICES[0] && SERVICES[0].id);
    const sel = document.getElementById("service-select");
    if (sel) {
      sel.innerHTML = SERVICES.map(
        (s) => `<option value="${s.id}">${escapeHtml(s.name)}</option>`,
      ).join("");
      sel.value = CURRENT_SERVICE;
      sel.onchange = () => {
        CURRENT_SERVICE = sel.value;
        const caps = SERVICE_MAP[CURRENT_SERVICE]?.capabilities || [];
        updateCapabilityVisibility(caps);
        refreshServiceData(caps);
      };
    }
    // Apply capability gating for the initial service
    if (CURRENT_SERVICE && SERVICE_MAP[CURRENT_SERVICE]) {
      updateCapabilityVisibility(SERVICE_MAP[CURRENT_SERVICE].capabilities || []);
    }
    renderServiceCheckboxes();
  } catch (err) {
    console.error("services load failed:", err);
  }
}

// Refresh every service-scoped panel in the Services tab. Called when
// switching services in the dropdown so the user doesn't see stale data
// from the previously selected server. Capability-gated panels are only
// hit when the new service actually supports them.
function refreshServiceData(caps) {
  // Clear user-action output boxes that only populate on demand —
  // otherwise they'd show results from the previous service.
  const whitelistOut = document.getElementById("whitelist-output");
  if (whitelistOut) { whitelistOut.textContent = ""; whitelistOut.classList.remove("visible"); }
  const cmdOut = document.getElementById("cmd-output");
  if (cmdOut) { cmdOut.textContent = ""; cmdOut.classList.remove("visible"); }

  // Clear lists that won't be repopulated (capability missing on the
  // new service) so old entries don't linger behind a hidden panel.
  if (!caps.includes("worlds")) {
    const worldList = document.getElementById("world-list");
    if (worldList) worldList.innerHTML = "";
  }
  if (!caps.includes("backup")) {
    const backupList = document.getElementById("backup-list");
    if (backupList) backupList.innerHTML = "";
  }
  const logOut = document.getElementById("log-output");
  if (logOut) { logOut.textContent = ""; logOut.classList.remove("visible"); }

  // Refresh everything the new service does support.
  refreshStatus();
  if (caps.includes("worlds")) loadWorlds();
  if (caps.includes("backup")) listBackups();
  if (caps.includes("logs")) loadLogs();
  pollCount = 0;
}

function renderServiceCheckboxes() {
  const wrap = document.getElementById("user-service-checkboxes");
  if (!wrap || SERVICES.length < 2) { if (wrap) wrap.innerHTML = ""; return; }
  wrap.innerHTML = `<span class="checkbox-label">${t("users.allowed_services")}:</span> ` +
    SERVICES.map((s) =>
      `<label class="service-cb">
        <input type="checkbox" value="${escapeAttr(s.id)}" checked> ${escapeHtml(s.name)}
      </label>`
    ).join(" ");
}

function getSelectedServices() {
  const boxes = document.querySelectorAll("#user-service-checkboxes input[type=checkbox]");
  if (boxes.length === 0) return SERVICES.map((s) => s.id);
  const ids = [];
  for (const cb of boxes) { if (cb.checked) ids.push(cb.value); }
  return ids;
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
  const status = await api(`/admin/api/services/${CURRENT_SERVICE}/status`);
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
  const caps = SERVICE_MAP[CURRENT_SERVICE]?.capabilities || [];
  if (caps.includes("rcon")) {
    document.getElementById("rcon-status").textContent =
      details.rconConnected ? "Connected" : "Disconnected";
  }
}

// Slow-poll worlds and backups (every 30s)
let pollCount = 0;
function poll() {
  if (activeTab === "services") {
    refreshStatus();
    pollCount++;
    if (pollCount % 3 === 0) {
      const caps = SERVICE_MAP[CURRENT_SERVICE]?.capabilities || [];
      if (caps.includes("worlds")) loadWorlds();
      if (caps.includes("backup")) listBackups();
    }
  } else if (activeTab === "play") {
    pollCount++;
    if (pollCount % 3 === 0) {
      loadPlayerOverview();
    }
  } else {
    pollCount++;
    if (pollCount % 3 === 0) {
      loadActiveSessions();
    }
  }
}

let pollTimer = null;

function startPolling() {
  if (pollTimer) return;
  pollTimer = setInterval(poll, 15000);
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
    if (activeTab === "services") {
      refreshStatus();
      const caps = SERVICE_MAP[CURRENT_SERVICE]?.capabilities || [];
      if (caps.includes("worlds")) loadWorlds();
      if (caps.includes("backup")) listBackups();
    } else if (activeTab === "play") {
      loadPlayerOverview();
    } else {
      loadActiveSessions();
    }
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
  const data = await api(`/admin/api/services/${CURRENT_SERVICE}/${route.path}`, {
    method: route.method,
  });
  if (data) toast(data.message || data.error || "OK");
}

// --- Gamemode (sent via the whitelisted RCON /command route) ---
async function setGamemode(mode) {
  if (!CURRENT_SERVICE) return;
  const data = await api(
    `/admin/api/services/${CURRENT_SERVICE}/command/${encodeURIComponent("gamemode " + mode + " @a")}`,
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
    `/admin/api/services/${CURRENT_SERVICE}/command/${encodeURIComponent(cmd)}`,
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
  const data = await api(`/admin/api/services/${CURRENT_SERVICE}/whitelist/${action}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ player }),
  });
  if (data) toast(data.response || data.error || "OK");
}

async function showWhitelist() {
  if (!CURRENT_SERVICE) return;
  const data = await api(`/admin/api/services/${CURRENT_SERVICE}/whitelist`);
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
  const data = await api(`/admin/api/services/${CURRENT_SERVICE}/${action}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ player }),
  });
  if (data) toast(data.response || data.error || "OK");
}

// --- Worlds ---
async function loadWorlds() {
  if (!CURRENT_SERVICE) return;
  const data = await api(`/admin/api/services/${CURRENT_SERVICE}/worlds`);
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
  const data = await api(`/admin/api/services/${CURRENT_SERVICE}/worlds/save-current`, {
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
    `/admin/api/services/${CURRENT_SERVICE}/worlds/${encodeURIComponent(name)}/switch`,
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
    `/admin/api/services/${CURRENT_SERVICE}/worlds/${encodeURIComponent(name)}/new`,
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
  const data = await api(`/admin/api/services/${CURRENT_SERVICE}/backups`);
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
    `/admin/api/services/${CURRENT_SERVICE}/backups/${encodeURIComponent(name)}/restore`,
    { method: "POST" },
  );
  if (data) toast(data.message || data.error || "OK");
}

// --- Firewall ---
async function loadFirewallRules() {
  const data = await api("/admin/api/firewall");
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
              // A rule may hold both an IPv4 and IPv6 address. Show
              // each on its own line so the admin can tell what's
              // covered. Removal is done by any of the IPs — we pass
              // the first one as the key.
              const ips = Array.isArray(r.ips) ? r.ips : (r.ip ? [r.ip] : []);
              const ipHtml = ips.map((ip) => escapeHtml(ip)).join("<br>");
              const primaryIp = ips[0] || "";
              return `<li class="firewall-item">
                <span>
                  <span class="firewall-ip">${ipHtml}</span>
                  <span class="firewall-meta">${meta}</span>
                </span>
                <button onclick="removeFirewallIp('${escapeHtml(primaryIp)}')" class="btn btn-sm btn-red">Remove</button>
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

/**
 * Try to fetch an IP from an ipify endpoint with a short timeout.
 * `api.ipify.org` has only an A record → the browser is forced to use
 * IPv4 to reach it, so the returned IP is guaranteed to be the v4
 * address. `api6.ipify.org` has only AAAA → forced v6. That's the
 * whole trick for dual-stack detection from a browser.
 */
async function fetchIpifyFamily(host) {
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 3000);
    const res = await fetch(`https://${host}`, {
      method: "GET",
      signal: ctrl.signal,
      referrerPolicy: "no-referrer",
      mode: "cors",
      credentials: "omit",
      cache: "no-store",
    });
    clearTimeout(timer);
    if (!res.ok) return null;
    const txt = (await res.text()).trim();
    if (!txt || txt.length > 64) return null;
    return txt;
  } catch {
    return null;
  }
}

async function detectPublicIps() {
  // Kick off the three lookups in parallel:
  //   - server-side union (req.ip + server's own v4/v6 upstream)
  //   - client-side forced IPv4 via api.ipify.org (A-only)
  //   - client-side forced IPv6 via api6.ipify.org (AAAA-only)
  //
  // Browser privacy protections (Firefox ETP, Safari ITP, ad blockers)
  // may block one or both ipify calls; that's fine, we still have the
  // server-side result. Conversely if the server is on a v4-only host
  // we'll miss the v6 side unless the browser provides it. The union
  // of all three is the most reliable answer.
  const [srv, v4, v6] = await Promise.all([
    api("/admin/api/public-ip").catch(() => null),
    fetchIpifyFamily("api.ipify.org"),
    fetchIpifyFamily("api6.ipify.org"),
  ]);
  const seen = new Set();
  const out = [];
  const push = (ip) => {
    if (typeof ip !== "string") return;
    const trimmed = ip.trim();
    if (!trimmed || seen.has(trimmed)) return;
    seen.add(trimmed);
    out.push(trimmed);
  };
  if (srv && srv.success) {
    if (Array.isArray(srv.ips)) srv.ips.forEach(push);
    else if (srv.ip) push(srv.ip);
  }
  push(v4);
  push(v6);
  return out;
}

async function allowMyIp() {
  toast("Detecting your public IP...");
  const ips = await detectPublicIps();
  if (ips.length === 0) {
    return toast("Could not detect your public IP. Use manual input instead.", "error");
  }
  const summary = ips.length === 1 ? ips[0] : `${ips.join(" + ")} (dual-stack)`;
  if (!confirm(`Allow your public IP(s) ${summary}?`)) return;
  const data = await api("/admin/api/firewall/add", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ips, label: "My IP" }),
  });
  if (data) {
    toast(data.message || data.error || "OK", data.success ? "success" : "error");
    loadFirewallRules();
  }
}

async function addFirewallIp() {
  const input = document.getElementById("firewall-ip").value.trim();
  const label = document.getElementById("firewall-label").value.trim();
  if (!input) return toast("Enter an IP address", "error");
  // Allow comma- or whitespace-separated entries so an admin can paste
  // a v4 and v6 address together when they know both.
  const ips = input.split(/[\s,]+/u).filter(Boolean);
  const data = await api("/admin/api/firewall/add", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ips, label }),
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
  const data = await api("/admin/api/firewall/remove", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ips: [ip] }),
  });
  if (data) {
    toast(data.message || data.error || "OK", data.success ? "success" : "error");
    loadFirewallRules();
  }
}

// --- Logs ---
async function loadLogs() {
  if (!CURRENT_SERVICE) return;
  const data = await api(`/admin/api/services/${CURRENT_SERVICE}/logs?lines=100`);
  const output = document.getElementById("log-output");
  if (data && data.logs) {
    output.textContent = data.logs.join("\n");
    output.classList.add("visible");
    output.scrollTop = output.scrollHeight;
  }
}

// --- Users (per-player knock links) ---------------------------------------
function serviceNameById(id) {
  const s = SERVICES.find((x) => x.id === id);
  return s ? s.name : id;
}

// User list was moved into the Directory card. This function is kept as
// a no-op so existing callers (tab switch, add/delete) don't break.
async function loadUsers() {}

async function addUser() {
  const input = document.getElementById("user-name");
  const name = input.value.trim();
  if (!name) return toast(t("users.placeholder_name"), "error");
  const allowedServices = getSelectedServices();
  if (allowedServices.length === 0) return toast(t("users.no_services_selected"), "error");
  const data = await api("/admin/api/users", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, allowedServices }),
  });
  if (data && data.success) {
    input.value = "";
    const url = `${window.location.origin}/u/${data.token}`;
    try { await navigator.clipboard.writeText(url); } catch { /* ignore */ }
    prompt(t("users.copy_link_done"), url);
    loadDirectory();
  } else if (data) {
    toast(data.error || "Failed", "error");
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
  if (entry.suspended) {
    return `<span class="badge badge-suspended">${t("directory.suspended")}</span>`;
  }
  if (entry.registrationOpenUntil) {
    return `<span class="badge badge-warn">${t("directory.enroll_open")}</span>`;
  }
  if (!entry.credentials || entry.credentials.length === 0) {
    return `<span class="muted">${t("directory.token_only")}</span>`;
  }
  return `<span class="badge badge-ok">${t("directory.active")}</span>`;
}

// Cache the most recent directory payload so the edit-services modal
// can look up the row's current allowedServices without re-fetching.
let DIRECTORY_ENTRIES = [];

async function loadDirectory() {
  const data = await api("/admin/api/directory");
  const body = document.getElementById("directory-body");
  if (!body) return;
  if (!data || !data.entries || data.entries.length === 0) {
    DIRECTORY_ENTRIES = [];
    body.innerHTML = `<tr><td colspan="7" class="muted">${t("directory.empty")}</td></tr>`;
    return;
  }
  DIRECTORY_ENTRIES = data.entries;
  body.innerHTML = data.entries
    .map((e) => {
      const roleLabel =
        e.role === "admin" ? t("directory.role_admin") : t("directory.role_player");
      const devices = (e.credentials || []).length;
      // Services column: only meaningful for knock users; admins have
      // access to everything through /admin, so render a dash instead.
      let servicesCell = `<span class="muted">—</span>`;
      if (e.kind === "knock") {
        const names = (e.allowedServices || []).map(serviceNameById);
        servicesCell = names.length
          ? escapeHtml(names.join(", "))
          : `<span class="muted">${t("directory.edit_services_none")}</span>`;
      }
      // Actions column for knock users: single "Manage" button opens modal.
      let actionsCell = `<span class="muted">—</span>`;
      if (e.kind === "knock") {
        actionsCell = `<button class="btn btn-sm" onclick="openManageModal('${escapeAttr(e.id)}')">${t("directory.manage")}</button>`;
      }
      return `<tr>
        <td><strong>${escapeHtml(e.name)}</strong></td>
        <td>${escapeHtml(roleLabel)}</td>
        <td>${servicesCell}</td>
        <td>${devices}</td>
        <td>${escapeHtml(formatRelative(e.lastSeenAt))}</td>
        <td>${directoryStatusCell(e)}</td>
        <td>${actionsCell}</td>
      </tr>`;
    })
    .join("");
}

// ---- Manage player modal -------------------------------------------------
let MANAGE_USER_ID = null;
let MANAGE_USER_NAME = null;

function openManageModal(userId) {
  const entry = DIRECTORY_ENTRIES.find((e) => e.id === userId && e.kind === "knock");
  if (!entry) {
    toast(t("common.error"), "error");
    return;
  }
  MANAGE_USER_ID = userId;
  MANAGE_USER_NAME = entry.name;
  document.getElementById("manage-modal-name").textContent = entry.name;

  // Populate service checkboxes
  const wrap = document.getElementById("manage-services-checkboxes");
  const current = new Set(entry.allowedServices || []);
  wrap.innerHTML = SERVICES.map((s) => {
    const checked = current.has(s.id) ? "checked" : "";
    return `<label class="service-cb">
      <input type="checkbox" value="${escapeAttr(s.id)}" ${checked}> ${escapeHtml(s.name)}
    </label>`;
  }).join(" ");

  // Suspend / reinstate button
  const suspBtn = document.getElementById("manage-suspend-btn");
  if (entry.suspended) {
    suspBtn.textContent = t("btn.reinstate");
    suspBtn.className = "btn btn-sm btn-green";
    suspBtn.onclick = manageReinstate;
  } else {
    suspBtn.textContent = t("btn.suspend");
    suspBtn.className = "btn btn-sm btn-red";
    suspBtn.onclick = manageSuspend;
  }

  document.getElementById("manage-modal").classList.remove("hidden");
}

function closeManageModal() {
  MANAGE_USER_ID = null;
  MANAGE_USER_NAME = null;
  document.getElementById("manage-modal").classList.add("hidden");
}

async function saveManageServices() {
  if (!MANAGE_USER_ID) return;
  const boxes = document.querySelectorAll(
    "#manage-services-checkboxes input[type=checkbox]",
  );
  const allowedServices = [];
  for (const cb of boxes) if (cb.checked) allowedServices.push(cb.value);
  const data = await api(`/admin/api/users/${MANAGE_USER_ID}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ allowedServices }),
  });
  if (data && data.success) {
    const name = (data.user && data.user.name) || "";
    toast(t("directory.edit_services_saved", { name }), "success");
    loadDirectory();
  } else if (data) {
    toast(data.error || "Failed", "error");
  }
}

async function manageNewLink() {
  if (!MANAGE_USER_ID) return;
  if (!confirm(t("users.rotate_confirm", { name: MANAGE_USER_NAME }))) return;
  const data = await api(`/admin/api/users/${MANAGE_USER_ID}/rotate-token`, { method: "POST" });
  if (data && data.success) {
    const url = `${window.location.origin}/u/${data.token}`;
    try { await navigator.clipboard.writeText(url); } catch { /* ignore */ }
    prompt(t("users.rotate_done", { name: MANAGE_USER_NAME }), url);
  }
}

async function manageRevoke() {
  if (!MANAGE_USER_ID) return;
  if (!confirm(t("users.revoke_confirm", { name: MANAGE_USER_NAME }))) return;
  const data = await api(`/admin/api/users/${MANAGE_USER_ID}/revoke`, { method: "POST" });
  if (data && data.success) {
    toast(t("users.revoked", { name: MANAGE_USER_NAME }), "success");
    loadDirectory();
  }
}

async function manageSuspend() {
  if (!MANAGE_USER_ID) return;
  if (!confirm(t("directory.suspend_confirm", { name: MANAGE_USER_NAME }))) return;
  const data = await api(`/admin/api/users/${MANAGE_USER_ID}/suspend`, { method: "POST" });
  if (data && data.success) {
    toast(t("directory.suspended_done", { name: MANAGE_USER_NAME }), "success");
    closeManageModal();
    loadDirectory();
  }
}

async function manageReinstate() {
  if (!MANAGE_USER_ID) return;
  if (!confirm(t("directory.reinstate_confirm", { name: MANAGE_USER_NAME }))) return;
  const data = await api(`/admin/api/users/${MANAGE_USER_ID}/reinstate`, { method: "POST" });
  if (data && data.success) {
    toast(t("directory.reinstated_done", { name: MANAGE_USER_NAME }), "success");
    closeManageModal();
    loadDirectory();
  }
}

async function manageDelete() {
  if (!MANAGE_USER_ID) return;
  if (!confirm(`${t("common.delete")} ${MANAGE_USER_NAME}?`)) return;
  const data = await api(`/admin/api/users/${MANAGE_USER_ID}`, { method: "DELETE" });
  if (data && data.success) {
    toast(t("users.deleted", { name: MANAGE_USER_NAME }), "success");
    closeManageModal();
    loadDirectory();
  }
}

// --- Active sessions ------------------------------------------------------
async function loadActiveSessions() {
  const data = await api("/admin/api/active-sessions");
  const list = document.getElementById("active-sessions-list");
  if (!list || !data || !data.sessions) return;
  if (data.sessions.length === 0) {
    list.innerHTML = `<li class="muted">${t("users.no_users")}</li>`;
    return;
  }
  list.innerHTML = data.sessions
    .map((s) => {
      const ips = Array.isArray(s.ips) ? s.ips : (s.ip ? [s.ip] : []);
      const playing = s.services.find((sv) => sv.connected);
      let label;
      if (playing) {
        label = t("active.connected", { service: playing.name });
      } else if (ips.length > 0) {
        label = t("active.idle_allowed");
      } else {
        label = t("active.idle_unallowed");
      }
      const ipText = ips.length > 0 ? ` · ${escapeHtml(ips.join(", "))}` : "";
      const roleBadge = s.role === "admin" ? ` <span class="badge badge-ok" style="font-size:0.7rem;padding:1px 6px">${t("directory.role_admin")}</span>` : "";
      return `<li class="firewall-item">
        <span><strong>${escapeHtml(s.name)}</strong>${roleBadge}
          <span class="firewall-meta">${escapeHtml(label)}${ipText}</span>
        </span>
      </li>`;
    })
    .join("");
}

// --- Stats leaderboard ----------------------------------------------------
async function loadStatsLeaderboard() {
  const data = await api("/admin/api/stats");
  const targets = [
    document.getElementById("stats-leaderboard"),
    document.getElementById("play-stats-leaderboard"),
  ].filter(Boolean);
  if (targets.length === 0 || !data || !data.leaderboard) return;
  let html;
  if (data.leaderboard.length === 0) {
    html = `<li class="muted">${t("stats.no_data")}</li>`;
  } else {
    // Map userId → name via /api/users
    const usersData = await api("/admin/api/users");
    const nameById = {};
    if (usersData && usersData.users) {
      for (const u of usersData.users) nameById[u.id] = u.name;
    }
    html = data.leaderboard
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
  for (const el of targets) el.innerHTML = html;
}

// ---- Play tab (mirrors the player PWA) ----------------------------------
let playCountdownTimer = null;
const IS_MOBILE = /iPhone|iPad|iPod|Android/i.test(navigator.userAgent);

function parseHostPort(addr) {
  if (!addr) return null;
  const i = addr.lastIndexOf(":");
  if (i <= 0) return { host: addr, port: null };
  const p = parseInt(addr.substring(i + 1), 10);
  return { host: addr.substring(0, i), port: Number.isNaN(p) ? null : p };
}
function playImpostorParams(s) {
  if (!s.connectHelper || s.connectHelper.type !== "impostor" || !s.connectAddress) return null;
  const parsed = parseHostPort(s.connectAddress);
  if (!parsed) return null;
  const scheme = s.connectHelper.scheme || "http";
  return { host: parsed.host, port: parsed.port || (scheme === "https" ? 443 : 22023), scheme, name: s.connectHelper.name || s.name };
}
function playImpostorDeepLink(host, port, scheme, name) {
  const params = new URLSearchParams({ servername: name, serverport: String(port), serverip: scheme + "://" + host, usedtls: "false" });
  return "amongus://init?" + params.toString();
}
function playImpostorRegionInfo(host, port, scheme, name) {
  return JSON.stringify({ CurrentRegionIdx: 3, Regions: [{ "$type": "StaticHttpRegionInfo, Assembly-CSharp", Name: name, PingServer: host, Servers: [{ Name: "http-1", Ip: scheme + "://" + host, Port: port, UseDtls: false }], TranslateName: 1003 }] }, null, 2);
}
function playImpostorActionInline(s) {
  const p = playImpostorParams(s);
  if (!p) return "";
  if (IS_MOBILE) {
    return `<a class="impostor-btn-inline" href="${escapeAttr(playImpostorDeepLink(p.host, p.port, p.scheme, p.name))}">${t("impostor.open_app")}</a>`;
  }
  return `<button class="impostor-btn-inline" data-impostor-dl data-host="${escapeAttr(p.host)}" data-port="${p.port}" data-scheme="${escapeAttr(p.scheme)}" data-name="${escapeAttr(p.name)}">${t("impostor.download_config")}</button>`;
}
function playImpostorActionBlock(s) {
  const p = playImpostorParams(s);
  if (!p) return "";
  if (IS_MOBILE) {
    return `<a class="impostor-btn" href="${escapeAttr(playImpostorDeepLink(p.host, p.port, p.scheme, p.name))}">${t("impostor.open_app")}</a>` +
      `<p class="helper-hint muted">${t("impostor.hint_mobile")}</p>`;
  }
  return `<button class="impostor-btn" data-impostor-dl data-host="${escapeAttr(p.host)}" data-port="${p.port}" data-scheme="${escapeAttr(p.scheme)}" data-name="${escapeAttr(p.name)}">${t("impostor.download_config")}</button>` +
    `<div class="helper-hint muted"><p>${t("impostor.hint_desktop")}</p>` +
    `<p class="impostor-path" data-copy="${escapeAttr(t("impostor.path_windows"))}" title="${t("service.click_to_copy")}">${escapeHtml(t("impostor.path_windows"))}</p>` +
    `<p>${t("impostor.hint_desktop_after")}</p></div>`;
}
function wirePlayImpostorDownloads() {
  for (const el of document.querySelectorAll("#tab-play [data-impostor-dl]")) {
    el.onclick = function () {
      const d = this.dataset;
      const json = playImpostorRegionInfo(d.host, parseInt(d.port, 10), d.scheme, d.name);
      const blob = new Blob([json], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = "regionInfo.json";
      document.body.appendChild(a); a.click();
      URL.revokeObjectURL(url); a.remove();
      toast(t("impostor.downloaded"), "success");
    };
  }
}

async function playKnock(force = false) {
  const btn = $("play-knock-btn");
  btn.disabled = true;
  const ips = await detectPublicIps();
  if (ips.length === 0) {
    btn.disabled = false;
    btn.textContent = t("btn.knock_all");
    return toast("Could not detect your public IP", "error");
  }
  // Use /self-knock which replaces the admin's own auto-rule (keyed on
  // adminId) with smart-revoke check for active sessions. /firewall/add
  // still exists for admins who want to add arbitrary IPs manually.
  let res;
  try {
    res = await fetch("/admin/api/firewall/self-knock", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ips, force }),
    });
  } catch (err) {
    btn.disabled = false;
    return toast(err.message, "error");
  }
  const data = await res.json().catch(() => ({}));
  btn.disabled = false;

  if (res.status === 409 && data.requireConfirm === "active_session") {
    const ok = confirm(
      `Your old IP (${(data.oldIps || []).join(", ")}) still has an active game session (${data.matchCount} connection${data.matchCount === 1 ? "" : "s"}). Replace it with your new IP anyway?`,
    );
    if (!ok) return;
    return playKnock(true);
  }

  if (data && data.success) {
    toast(t("knock.success"), "success");
  } else {
    toast((data && data.error) || "Failed", "error");
  }
  refreshPlayState();
  refreshPlayActive();
}

async function playRevoke() {
  const data = await api("/admin/api/firewall/self-revoke", { method: "POST" });
  if (data && data.success) {
    toast(data.removed ? "Revoked" : "No active rule", "success");
  } else if (data) {
    toast(data.error || "Failed", "error");
  }
  refreshPlayState();
}

async function refreshPlayState() {
  const fwData = await api("/admin/api/firewall");
  const knockBtn = $("play-knock-btn");
  const statusEl = $("play-status");
  const revokeBtn = $("play-revoke-btn");
  const mapLinksEl = $("play-map-links");
  const svcCard = $("play-services-card");
  const svcList = $("play-services-list");

  let myRule = null;
  if (fwData && fwData.rules) {
    // Prefer this admin's own self-knock rule (keyed on adminId).
    // Fall back to any admin-type rule (no userId) for backwards
    // compatibility with pre-adminId rules still on disk.
    myRule =
      fwData.rules.find((r) => r.adminId && r.adminId === CURRENT_ADMIN_ID) ??
      fwData.rules.find((r) => !r.userId && !r.adminId);
  }

  revokeBtn.hidden = !myRule;
  if (myRule) {
    knockBtn.classList.add("ok");
    knockBtn.textContent = t("knock.ready");
    knockBtn.disabled = false;
    const update = () => {
      if (!myRule.expiresAt) { statusEl.textContent = ""; return; }
      const remain = new Date(myRule.expiresAt).getTime() - Date.now();
      if (remain <= 0) {
        statusEl.textContent = t("knock.never");
        knockBtn.classList.remove("ok");
        knockBtn.textContent = t("btn.knock_all");
        clearInterval(playCountdownTimer);
        return;
      }
      const h = Math.floor(remain / 3600000);
      const m = Math.floor((remain % 3600000) / 60000);
      statusEl.textContent = t("knock.expires_in", { hours: h, minutes: m });
    };
    update();
    clearInterval(playCountdownTimer);
    playCountdownTimer = setInterval(update, 30000);
  } else {
    statusEl.textContent = t("knock.never");
    knockBtn.classList.remove("ok");
    knockBtn.textContent = t("btn.knock_all");
    knockBtn.disabled = false;
    clearInterval(playCountdownTimer);
  }

  // Connection info helper (identical to PWA)
  function connectInfo(s) {
    if (s.connectAddress) {
      return `<span class="connect-addr" title="${t("service.click_to_copy")}" data-copy="${escapeAttr(s.connectAddress)}">${escapeHtml(s.connectAddress)}</span>`;
    }
    if (s.ports && s.ports.length > 0) {
      const portStr = s.ports.map((p) => `${p.port}/${p.proto}`).join(", ");
      return `<span class="connect-ports muted">${escapeHtml(portStr)}</span>`;
    }
    return "";
  }

  // Per-service list (multi) or inline connect info (single)
  if (SERVICES.length > 1) {
    svcCard.hidden = false;
    svcList.innerHTML = SERVICES.map((s) => {
      const actions = [];
      if (s.mapUrl) {
        actions.push(`<a class="map-link-inline" href="${escapeAttr(s.mapUrl)}" target="_blank" rel="noopener"><span class="map-icon">&#x1f5fa;&#xfe0e;</span> ${t("btn.view_map")}</a>`);
      }
      const imp = playImpostorActionInline(s);
      if (imp) {
        actions.push(imp);
      } else if (s.connectGuideUrl) {
        actions.push(`<a class="guide-link-inline" href="${escapeAttr(s.connectGuideUrl)}" target="_blank" rel="noopener">${t("btn.setup_guide")}</a>`);
      }
      const impHelp = (!IS_MOBILE && playImpostorParams(s))
        ? `<div class="impostor-help-row"><p>${t("impostor.hint_desktop")}</p><p><span class="impostor-path" data-copy="${escapeAttr(t("impostor.path_windows"))}" title="${t("service.click_to_copy")}">${escapeHtml(t("impostor.path_windows"))}</span></p><p>${t("impostor.hint_desktop_after")}</p></div>`
        : "";
      return `<li${impHelp ? ' class="li-wrap"' : ''}>` +
        `<div class="li-info"><span>${escapeHtml(s.name)}</span><div class="connect-row">${connectInfo(s)}</div></div>` +
        (actions.length > 0 ? `<span class="li-actions">${actions.join(" ")}</span>` : "") +
        impHelp + `</li>`;
    }).join("");
  } else if (SERVICES.length === 1) {
    svcCard.hidden = true;
    const s = SERVICES[0];
    const parts = [];
    if (s.connectAddress || (s.ports && s.ports.length > 0)) parts.push(connectInfo(s));
    if (s.mapUrl) {
      parts.push(`<a class="map-link" href="${escapeAttr(s.mapUrl)}" target="_blank" rel="noopener"><span class="map-icon">&#x1f5fa;&#xfe0e;</span> ${escapeHtml(t("btn.view_map"))}</a>`);
    }
    const impBlock = playImpostorActionBlock(s);
    if (impBlock) {
      parts.push(impBlock);
    } else if (s.connectGuideUrl) {
      parts.push(`<a class="guide-link" href="${escapeAttr(s.connectGuideUrl)}" target="_blank" rel="noopener">${escapeHtml(t("btn.setup_guide"))}</a>`);
    }
    mapLinksEl.innerHTML = parts.join("");
  }

  // Wire click-to-copy and impostor downloads
  for (const el of document.querySelectorAll("#tab-play [data-copy]")) {
    el.onclick = () => {
      navigator.clipboard.writeText(el.dataset.copy).then(() => toast(t("service.copied"), "success")).catch(() => {});
    };
  }
  wirePlayImpostorDownloads();
}

async function refreshPlayActive() {
  const sessData = await api("/admin/api/active-sessions");
  const activeList = $("play-active-list");
  const sessions = (sessData && sessData.sessions) || [];
  if (sessions.length === 0) {
    activeList.innerHTML = `<li class="muted">${t("stats.no_data")}</li>`;
    return;
  }
  activeList.innerHTML = sessions.map((s) => {
    const ips = Array.isArray(s.ips) ? s.ips : [];
    const playing = s.services.find((sv) => sv.connected);
    const allowed = ips.length > 0;
    let dot = "gray", label;
    if (s.suspended) {
      dot = "gray"; label = t("directory.suspended");
    } else if (playing) {
      dot = "green"; label = t("active.connected", { service: playing.name });
    } else if (allowed) {
      dot = "yellow"; label = t("active.idle_allowed");
    } else {
      label = t("active.idle_unallowed");
    }
    return `<li><span><span class="dot ${dot}"></span>${escapeHtml(s.name)}</span><span class="muted">${escapeHtml(label)}</span></li>`;
  }).join("");
}

function initPlayTab() {
  const greeting = $("play-greeting");
  if (greeting) greeting.textContent = "Admin";
  const knockBtn = $("play-knock-btn");
  knockBtn.textContent = t("btn.knock_all");
  knockBtn.disabled = false;
  knockBtn.addEventListener("click", () => playKnock());
  const revokeBtn = $("play-revoke-btn");
  revokeBtn.textContent = t("btn.revoke");
  revokeBtn.addEventListener("click", () => playRevoke());
  $("play-status").textContent = t("knock.never");
}

function loadPlayerOverview() {
  refreshPlayState();
  refreshPlayActive();
}

// ---- Dashboard boot (called after successful login) ---------------------
async function bootApp() {
  initTabs();
  initPlayTab();
  await loadServices();
  // Services tab is active by default — load its data
  refreshStatus();
  const caps = SERVICE_MAP[CURRENT_SERVICE]?.capabilities || [];
  if (caps.includes("worlds")) loadWorlds();
  if (caps.includes("backup")) listBackups();
  startPolling();
}

// ---- Admin management -----------------------------------------------------
let CURRENT_ADMIN_ID = null; // set after login from /me response

async function loadAdmins() {
  const data = await api("/admin/api/admins");
  const list = document.getElementById("admin-list");
  if (!list) return;
  if (!data || !data.admins || data.admins.length === 0) {
    list.innerHTML = "<li class=\"muted\">No admins found</li>";
    return;
  }
  list.innerHTML = data.admins.map((a) => {
    const keys = a.credentialCount === 1 ? "1 passkey" : `${a.credentialCount} passkeys`;
    const pending = a.credentialCount === 0
      ? ' <span class="badge badge-warn">invite pending</span>'
      : "";
    const isSelf = a.id === CURRENT_ADMIN_ID;
    const deleteBtn = isSelf
      ? ""
      : ` <button onclick="deleteAdmin('${escapeAttr(a.id)}','${escapeAttr(a.name)}')" class="btn btn-sm btn-red">Remove</button>`;
    return `<li class="firewall-item">
      <span><strong>${escapeHtml(a.name)}</strong> <span class="muted">${keys}</span>${pending}</span>
      <span>${deleteBtn}</span>
    </li>`;
  }).join("");
}

async function inviteAdmin() {
  const input = document.getElementById("invite-admin-name");
  const name = input.value.trim();
  if (!name) return toast("Enter a name for the new admin", "error");
  const data = await api("/admin/api/admins", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name }),
  });
  if (data && data.success) {
    input.value = "";
    try { await navigator.clipboard.writeText(data.inviteUrl); } catch { /* ignore */ }
    prompt("Invite link (copied to clipboard) — share with the new admin:", data.inviteUrl);
    loadAdmins();
  } else if (data) {
    toast(data.error || "Failed to create invite", "error");
  }
}

async function deleteAdmin(id, name) {
  if (!confirm(`Remove admin "${name}"? They will lose access immediately.`)) return;
  const data = await api(`/admin/api/admins/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
  if (data && data.success) {
    toast(`Admin "${name}" removed`, "success");
    loadAdmins();
    loadDirectory();
  } else if (data) {
    toast(data.error || "Failed", "error");
  }
}

// ---- Entry point ---------------------------------------------------------
loadI18n().then(() => checkSessionOrLogin());
