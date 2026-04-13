/**
 * Personal Knock PWA — auto-knocks on launch, refreshes while open,
 * and protects against accidentally swapping out the home IP via:
 *
 *   1. Anchor-IP guard (client side): before each knock we fetch the
 *      device's current public IPs (both v4 and v6) and compare against
 *      the server's *currently active* rule IPs via GET /state. If
 *      there's no overlap we show a blocking confirmation dialog
 *      instead of just swapping. We deliberately do NOT use localStorage
 *      here: the firewall rule is shared across all devices on the
 *      same account, so device B must see what device A already
 *      knocked — otherwise you get false "new IP" warnings just
 *      because device B's cache is stale.
 *
 *   2. Server smart-revoke (server side): even if the client guard is
 *      bypassed, the server checks ss/conntrack for live game traffic
 *      from any of the rule's IPs. If a session is live, the server
 *      returns 409 {requireConfirm: "active_session"} and we show a
 *      similar confirmation dialog before sending ?force=true.
 *
 * Dual-stack detection: the browser's own socket tells us only one
 * family (whichever Happy Eyeballs picked). To catch the other family
 * we call `api.ipify.org` (A-only DNS → forced IPv4) and
 * `api6.ipify.org` (AAAA-only DNS → forced IPv6) in parallel. Either
 * or both may fail (tracking protection, ad blocker, v6-less ISP);
 * whatever succeeds is sent to the server, which opens UFW rules for
 * all received addresses and relies on its own detection as the
 * fallback floor.
 */

(() => {
  const init = window.__INIT__ || {};
  const I18N = window.__I18N__ || {};
  const PORTAL_MODE = !!init.portalMode;
  const PORTAL_LOGIN = !!init.portalLogin;
  const TOKEN = init.token;
  const BASE = PORTAL_MODE ? "/my" : `/u/${TOKEN}`;
  const USER = init.user || {};
  const SERVICES = init.services || [];
  const REQUIRE_PASSKEY = !!init.requirePasskey;
  const KEEP_ALIVE_MS = 10 * 60 * 1000;     // re-knock every 10 min while open
  const STATE_REFRESH_MS = 30 * 1000;       // poll active sessions every 30 s
  const STORE_KEY = `knock-pwa:${USER.id || "u"}`;

  // ---- i18n helper ------------------------------------------------------
  function t(key, vars) {
    let s = I18N[key] || key;
    if (vars) {
      for (const [k, v] of Object.entries(vars)) {
        s = s.replace(new RegExp(`\\{${k}\\}`, "g"), String(v));
      }
    }
    return s;
  }

  // Apply data-i18n attributes
  for (const el of document.querySelectorAll("[data-i18n]")) {
    el.textContent = t(el.dataset.i18n);
  }

  // ---- localStorage state ----------------------------------------------
  function loadState() {
    try {
      return JSON.parse(localStorage.getItem(STORE_KEY) || "{}");
    } catch { return {}; }
  }
  function saveState(patch) {
    const cur = loadState();
    localStorage.setItem(STORE_KEY, JSON.stringify({ ...cur, ...patch }));
  }

  // ---- DOM refs ---------------------------------------------------------
  const $ = (id) => document.getElementById(id);
  const greeting = $("greeting");
  const status = $("status");
  const knockBtn = $("knock-all");
  const heroCard = $("hero-card");
  const heroMeta = $("hero-meta");
  const servicesCard = $("services-card");
  const servicesList = $("services-list");
  const activeList = $("active-list");
  const statsSummary = $("stats-summary");
  const statsWeek = $("stats-week");
  const mapLinksEl = $("map-links");
  const revokeBtn = $("revoke");
  const authCard = $("auth-card");
  const authDesc = $("auth-desc");
  const authRegisterBtn = $("auth-register");
  const authLoginBtn = $("auth-login");
  const authLocked = $("auth-locked");

  // Brand title from hostname
  const brandTitle = $("brand-title");
  if (brandTitle) brandTitle.textContent = window.location.hostname;

  greeting.textContent = USER.name ? `Hi ${USER.name}!` : "Welcome";
  knockBtn.textContent = t("btn.knock_all");
  status.textContent = t("knock.never");

  // ---- Toast ------------------------------------------------------------
  const toast = $("toast");
  let toastTimer = null;
  function showToast(msg, kind = "") {
    toast.textContent = msg;
    toast.className = `toast show ${kind}`;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      toast.className = "toast";
    }, 3000);
  }

  // ---- Confirmation dialog ---------------------------------------------
  function showDialog(title, body) {
    return new Promise((resolve) => {
      const dialog = $("dialog");
      $("dialog-title").textContent = title;
      $("dialog-body").textContent = body;
      $("dialog-cancel").textContent = t("knock.confirm_cancel");
      $("dialog-confirm").textContent = t("knock.confirm_continue");
      dialog.classList.add("open");
      const cleanup = (val) => {
        dialog.classList.remove("open");
        $("dialog-cancel").removeEventListener("click", onCancel);
        $("dialog-confirm").removeEventListener("click", onConfirm);
        dialog.removeEventListener("click", onBackdrop);
        resolve(val);
      };
      const onCancel = (e) => { e.stopPropagation(); cleanup(false); };
      const onConfirm = (e) => { e.stopPropagation(); cleanup(true); };
      const onBackdrop = (e) => { if (e.target === dialog) cleanup(false); };
      $("dialog-cancel").addEventListener("click", onCancel);
      $("dialog-confirm").addEventListener("click", onConfirm);
      dialog.addEventListener("click", onBackdrop);
    });
  }

  // ---- Public IP detection (anchor-IP guard) ---------------------------
  /**
   * Fetch an ipify endpoint with a short timeout. The host names carry
   * the forced-family trick: api.ipify.org has only an A record, so
   * the browser can only reach it over IPv4 and we always get the v4
   * address back. api6.ipify.org has only AAAA and forces IPv6.
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

  /**
   * Try to collect every public IP the device is reachable as.
   * Returns an array (possibly empty). The server gets this list as
   * `ips[]` and decides what to actually allow.
   */
  async function detectPublicIps() {
    const [server, v4, v6] = await Promise.all([
      fetch(`${BASE}/my-ip`).then((r) => r.json()).catch(() => null),
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
    if (server && server.success) {
      if (Array.isArray(server.ips)) server.ips.forEach(push);
      else if (server.ip) push(server.ip);
    }
    push(v4);
    push(v6);
    return out;
  }

  // ---- Knock --------------------------------------------------------------
  async function knock(serviceIds, { force = false, skipAnchorCheck = false } = {}) {
    // Collect the current public IPs up front so we can both anchor-
    // check and attach them to the POST body.
    const currentIps = await detectPublicIps();

    // Anchor-IP guard: compare the currently-detected IPs against the
    // server's active rule (authoritative, shared across all devices
    // for this user). If another device just knocked from a new
    // network, the rule already reflects that — so we shouldn't warn
    // on this device merely because its local cache is stale.
    if (!force && !skipAnchorCheck) {
      let serverIps = [];
      try {
        const r = await fetch(`${BASE}/state`);
        const d = await r.json();
        if (d && d.success && d.active && Array.isArray(d.active.ips)) {
          serverIps = d.active.ips;
        }
      } catch {
        // Silent fallback — no server state means no guard.
      }
      if (serverIps.length > 0 && currentIps.length > 0) {
        const serverSet = new Set(serverIps);
        const overlap = currentIps.some((ip) => serverSet.has(ip));
        if (!overlap) {
          const ok = await showDialog(
            t("knock.different_network_title"),
            t("knock.different_network_body", {
              oldIp: serverIps.join(", "),
              newIp: currentIps.join(", "),
            }),
          );
          if (!ok) return { aborted: true };
        }
      }
    }

    let res, data;
    try {
      res = await fetch(
        `${BASE}/knock${force ? "?force=true" : ""}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            services: serviceIds || "all",
            ips: currentIps,
          }),
        },
      );
      data = await res.json();
    } catch (err) {
      showToast(t("knock.failed", { error: err.message }), "error");
      return { error: err.message };
    }

    if (res.status === 409 && data.requireConfirm === "active_session") {
      const ok = await showDialog(
        t("knock.active_session_title"),
        t("knock.active_session_body", { seconds: data.lastSeenSecondsAgo || 0 }),
      );
      if (!ok) return { aborted: true };
      return knock(serviceIds, { force: true, skipAnchorCheck: true });
    }

    if (!res.ok || !data.success) {
      showToast(data.error || "Failed", "error");
      return { error: data.error };
    }

    if (data.ignored) {
      // IP is in an ignored range (CGNAT/Tailscale) — no firewall
      // rule needed. Just show success.
      showToast(t("knock.success"), "success");
      refreshState();
      refreshActive();
      refreshStats();
      return data;
    }

    saveState({ lastKnockAt: new Date().toISOString() });
    showToast(t("knock.success"), "success");
    refreshState();
    refreshActive();
    refreshStats();
    return data;
  }

  // ---- State refresh (active rule + countdown) -------------------------
  let countdownTimer = null;

  async function refreshState() {
    try {
      const res = await fetch(`${BASE}/state`);
      const data = await res.json();
      if (!data.success) return;

      const active = data.active;
      revokeBtn.hidden = !active;
      if (active) {
        knockBtn.classList.add("ok");
        const update = () => {
          const remain = new Date(active.expiresAt).getTime() - Date.now();
          if (remain <= 0) {
            status.textContent = t("knock.never");
            knockBtn.classList.remove("ok");
            knockBtn.textContent = t("btn.knock_all");
            clearInterval(countdownTimer);
            return;
          }
          const h = Math.floor(remain / 3600000);
          const m = Math.floor((remain % 3600000) / 60000);
          status.textContent = t("knock.expires_in", { hours: h, minutes: m });
          knockBtn.textContent = t("knock.ready");
        };
        update();
        clearInterval(countdownTimer);
        countdownTimer = setInterval(update, 30000);
      } else {
        status.textContent = t("knock.never");
        knockBtn.classList.remove("ok");
        knockBtn.textContent = t("btn.knock_all");
      }

      // Connection info helper
      function connectInfo(s) {
        if (s.connectAddress) {
          return `<span class="connect-addr" title="${t("service.click_to_copy")}"` +
            ` data-copy="${escapeAttr(s.connectAddress)}">${escapeHtml(s.connectAddress)}</span>`;
        }
        if (s.ports && s.ports.length > 0) {
          const portStr = s.ports.map((p) => `${p.port}/${p.proto}`).join(", ");
          return `<span class="connect-ports muted">${escapeHtml(portStr)}</span>`;
        }
        return "";
      }

      // Per-service list — service name + connection info on the left,
      // optional inline map link on the right. The big "Ready to play"
      // button at the top already knocks every service at once, so we
      // deliberately don't render a per-service knock button here; that
      // just crowded the row on narrow phone screens.
      if (SERVICES.length > 1) {
        servicesCard.hidden = false;
        servicesList.innerHTML = SERVICES.map(
          (s) => {
            const actions = [];
            if (s.mapUrl) {
              actions.push(
                `<a class="map-link-inline" href="${escapeAttr(s.mapUrl)}" target="_blank" rel="noopener">` +
                `<span class="map-icon">&#x1f5fa;&#xfe0e;</span> ${t("btn.view_map")}</a>`
              );
            }
            const imp = impostorActionInline(s);
            if (imp) {
              actions.push(imp);
            } else if (s.connectGuideUrl) {
              actions.push(
                `<a class="guide-link-inline" href="${escapeAttr(s.connectGuideUrl)}" target="_blank" rel="noopener">` +
                `${t("btn.setup_guide")}</a>`
              );
            }
            // Desktop path instructions for impostor services
            const impHelp = (!IS_MOBILE && impostorParams(s))
              ? `<div class="impostor-help-row">` +
                `<p>${t("impostor.hint_desktop")}</p>` +
                `<p><span class="impostor-path" data-copy="${escapeAttr(t("impostor.path_windows"))}" title="${t("service.click_to_copy")}">${escapeHtml(t("impostor.path_windows"))}</span></p>` +
                `<p>${t("impostor.hint_desktop_after")}</p>` +
                `</div>`
              : "";
            return `<li${impHelp ? ' class="li-wrap"' : ''}>` +
              `<div class="li-info"><span>${escapeHtml(s.name)}</span>` +
              `<div class="connect-row">${connectInfo(s)}</div></div>` +
              (actions.length > 0
                ? `<span class="li-actions">${actions.join(" ")}</span>`
                : "") +
              impHelp +
              `</li>`;
          },
        ).join("");
      }

      // Single-service: show connection info + map link under hero button
      if (SERVICES.length === 1) {
        const s = SERVICES[0];
        let parts = [];
        if (s.connectAddress || (s.ports && s.ports.length > 0)) {
          parts.push(connectInfo(s));
        }
        if (s.mapUrl) {
          parts.push(
            `<a class="map-link" href="${escapeAttr(s.mapUrl)}" target="_blank" rel="noopener">` +
            `<span class="map-icon">&#x1f5fa;&#xfe0e;</span> ${escapeHtml(t("btn.view_map"))}</a>`
          );
        }
        const impBlock = impostorActionBlock(s);
        if (impBlock) {
          parts.push(impBlock);
        } else if (s.connectGuideUrl) {
          parts.push(
            `<a class="guide-link" href="${escapeAttr(s.connectGuideUrl)}" target="_blank" rel="noopener">` +
            `${escapeHtml(t("btn.setup_guide"))}</a>`
          );
        }
        mapLinksEl.innerHTML = parts.join("");
      } else {
        mapLinksEl.innerHTML = "";
      }

      // Click-to-copy on connect addresses
      for (const el of document.querySelectorAll("[data-copy]")) {
        el.onclick = () => {
          navigator.clipboard.writeText(el.dataset.copy).then(() => {
            showToast(t("service.copied"), "success");
          }).catch(() => {});
        };
      }
      // Wire Impostor download buttons (desktop)
      wireImpostorDownloads();
    } catch (err) {
      console.error("refreshState failed:", err);
    }
  }

  // ---- Active sessions panel -------------------------------------------
  async function refreshActive() {
    try {
      const res = await fetch(`${BASE}/active`);
      const data = await res.json();
      if (!data.success) return;
      if (data.sessions.length === 0) {
        activeList.innerHTML = `<li class="muted">${t("common.unknown")}</li>`;
        return;
      }

      // ── Per-service summary: aggregate player counts + names ──
      const svcMap = {};
      for (const s of data.sessions) {
        for (const sv of s.services) {
          if (!svcMap[sv.id]) svcMap[sv.id] = { name: sv.name, players: [], connected: 0 };
          // playerNames comes from RCON (Minecraft) — use if available
          if (sv.playerNames && sv.playerNames.length > 0) {
            for (const p of sv.playerNames) {
              if (!svcMap[sv.id].players.includes(p)) svcMap[sv.id].players.push(p);
            }
          }
          if (sv.connected) svcMap[sv.id].connected++;
        }
      }

      const svcSummary = Object.values(svcMap)
        .filter((sv) => sv.players.length > 0 || sv.connected > 0)
        .map((sv) => {
          const count = sv.players.length || sv.connected;
          const names = sv.players.length > 0
            ? `<span class="svc-players">${sv.players.map(escapeHtml).join(", ")}</span>`
            : "";
          return `<li class="svc-summary-item">
            <span><span class="dot green"></span><strong>${escapeHtml(sv.name)}</strong></span>
            <span>${count} online</span>
            ${names ? `<div class="svc-summary-names">${names}</div>` : ""}
          </li>`;
        })
        .join("");

      // ── Per-user list (existing) ──
      const userList = data.sessions
        .map((s) => {
          const ips = Array.isArray(s.ips) ? s.ips : (s.ip ? [s.ip] : []);
          const playing = s.services.find((sv) => sv.connected);
          const allowed = ips.length > 0;
          let dot = "gray", txt = t("active.idle_unallowed");
          if (playing) {
            dot = "green";
            txt = t("active.connected", { service: playing.name });
          } else if (allowed) {
            dot = "yellow";
            txt = t("active.idle_allowed");
          }
          return `<li><span><span class="dot ${dot}"></span>${escapeHtml(s.name)}</span>
            <span class="muted">${escapeHtml(txt)}</span></li>`;
        })
        .join("");

      activeList.innerHTML =
        (svcSummary ? `<div class="svc-summary">${svcSummary}</div><hr class="active-divider">` : "") +
        userList;
    } catch (err) {
      console.error("refreshActive failed:", err);
    }
  }

  // ---- Stats panel ------------------------------------------------------
  async function refreshStats() {
    try {
      const res = await fetch(`${BASE}/stats`);
      const data = await res.json();
      if (!data.success || !data.stats) return;
      const s = data.stats;
      if (!s.totalSeconds) {
        statsSummary.textContent = t("stats.no_data");
        statsWeek.innerHTML = "";
        return;
      }
      statsSummary.textContent =
        t("stats.played_today", { time: fmtDuration(s.today) }) +
        " · " +
        t("stats.played_week", { time: fmtDuration(s.week) }) +
        " · " +
        t("stats.played_total", { time: fmtDuration(s.totalSeconds) });

      // Render last 7 days as bars (uses the per-day buckets fetched via /api/stats)
      try {
        const allRes = await fetch(`/api/stats`);
        const allData = await allRes.json();
        const u = allData.stats?.users?.[USER.id];
        if (u && u.perDay) {
          const days = [];
          for (let i = 6; i >= 0; i--) {
            const d = new Date();
            d.setDate(d.getDate() - i);
            const key = d.toISOString().slice(0, 10);
            const total = Object.values(u.perDay[key] || {}).reduce((a, b) => a + b, 0);
            days.push({ key, total });
          }
          const max = Math.max(...days.map((d) => d.total), 60);
          const today = new Date().toISOString().slice(0, 10);
          statsWeek.innerHTML = days
            .map((d) => {
              const pct = Math.max(3, Math.round((d.total / max) * 100));
              return `<div class="bar ${d.key === today ? "today" : ""}" style="height:${pct}%" title="${d.key}: ${fmtDuration(d.total)}"></div>`;
            })
            .join("");
        }
      } catch { /* ignore */ }
    } catch (err) {
      console.error("refreshStats failed:", err);
    }
  }

  function fmtDuration(s) {
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    if (h > 0) return `${h}${t("time.h_short")} ${m}${t("time.m_short")}`;
    return `${m}${t("time.m_short")}`;
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#039;");
  }
  function escapeAttr(s) {
    return escapeHtml(s);
  }

  // ---- Among Us / Impostor connect helper --------------------------------
  const IS_MOBILE = /iPhone|iPad|iPod|Android/i.test(navigator.userAgent);

  function parseHostPort(addr) {
    if (!addr) return null;
    const i = addr.lastIndexOf(":");
    if (i <= 0) return { host: addr, port: null };
    const p = parseInt(addr.substring(i + 1), 10);
    return { host: addr.substring(0, i), port: Number.isNaN(p) ? null : p };
  }

  function impostorDeepLink(host, port, scheme, name) {
    const params = new URLSearchParams({
      servername: name,
      serverport: String(port),
      serverip: scheme + "://" + host,
      usedtls: "false",
    });
    return "amongus://init?" + params.toString();
  }

  function impostorRegionInfo(host, port, scheme, name) {
    return JSON.stringify({
      CurrentRegionIdx: 3,
      Regions: [{
        $type: "StaticHttpRegionInfo, Assembly-CSharp",
        Name: name,
        PingServer: host,
        Servers: [{
          Name: "http-1",
          Ip: scheme + "://" + host,
          Port: port,
          UseDtls: false,
        }],
        TranslateName: 1003,
      }],
    }, null, 2);
  }

  function downloadFile(content, filename) {
    var blob = new Blob([content], { type: "application/json" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    URL.revokeObjectURL(url);
    a.remove();
  }

  function impostorParams(s) {
    if (!s.connectHelper || s.connectHelper.type !== "impostor" || !s.connectAddress) return null;
    var parsed = parseHostPort(s.connectAddress);
    if (!parsed) return null;
    var scheme = s.connectHelper.scheme || "http";
    return {
      host: parsed.host,
      port: parsed.port || (scheme === "https" ? 443 : 22023),
      scheme: scheme,
      name: s.connectHelper.name || s.name,
    };
  }

  /** Inline button for multi-service list */
  function impostorActionInline(s) {
    var p = impostorParams(s);
    if (!p) return "";
    if (IS_MOBILE) {
      return `<a class="impostor-btn-inline" href="${escapeAttr(impostorDeepLink(p.host, p.port, p.scheme, p.name))}">${t("impostor.open_app")}</a>`;
    }
    return `<button class="impostor-btn-inline" data-impostor-dl ` +
      `data-host="${escapeAttr(p.host)}" data-port="${p.port}" ` +
      `data-scheme="${escapeAttr(p.scheme)}" data-name="${escapeAttr(p.name)}">${t("impostor.download_config")}</button>`;
  }

  /** Block for single-service view */
  function impostorActionBlock(s) {
    var p = impostorParams(s);
    if (!p) return "";
    if (IS_MOBILE) {
      return `<a class="impostor-btn" href="${escapeAttr(impostorDeepLink(p.host, p.port, p.scheme, p.name))}">${t("impostor.open_app")}</a>` +
        `<p class="helper-hint muted">${t("impostor.hint_mobile")}</p>`;
    }
    return `<button class="impostor-btn" data-impostor-dl ` +
      `data-host="${escapeAttr(p.host)}" data-port="${p.port}" ` +
      `data-scheme="${escapeAttr(p.scheme)}" data-name="${escapeAttr(p.name)}">${t("impostor.download_config")}</button>` +
      `<div class="helper-hint muted">` +
      `<p>${t("impostor.hint_desktop")}</p>` +
      `<p class="impostor-path" data-copy="${escapeAttr(t("impostor.path_windows"))}" title="${t("service.click_to_copy")}">${escapeHtml(t("impostor.path_windows"))}</p>` +
      `<p class="impostor-path" data-copy="${escapeAttr(t("impostor.path_linux"))}" title="${t("service.click_to_copy")}">${escapeHtml(t("impostor.path_linux"))}</p>` +
      `<p>${t("impostor.hint_desktop_after")}</p>` +
      `</div>`;
  }

  function wireImpostorDownloads() {
    for (var el of document.querySelectorAll("[data-impostor-dl]")) {
      el.onclick = function () {
        var d = this.dataset;
        var json = impostorRegionInfo(d.host, parseInt(d.port, 10), d.scheme, d.name);
        downloadFile(json, "regionInfo.json");
        showToast(t("impostor.downloaded"), "success");
      };
    }
  }

  // ---- Wire up ----------------------------------------------------------
  knockBtn.addEventListener("click", async () => {
    const result = await knock("all");
    if (result && !result.aborted && !result.error) {
      startKeepAlive();
    }
  });
  revokeBtn.addEventListener("click", async () => {
    if (!confirm(t("users.revoke_confirm", { name: USER.name }))) return;
    try {
      await fetch(`${BASE}/revoke`, { method: "POST" });
      refreshState();
      showToast("Revoked", "success");
    } catch (err) {
      showToast(err.message, "error");
    }
  });

  // ---- Auth (Phase 3 optional passkey gate) ----------------------------
  let keepAliveTimer = null;
  let keepAliveActive = false;

  function startKeepAlive() {
    keepAliveActive = true;
    if (keepAliveTimer) return;
    keepAliveTimer = setInterval(() => {
      if (!document.hidden) {
        knock("all", { skipAnchorCheck: true }).catch(() => {});
      }
    }, KEEP_ALIVE_MS);
  }
  function stopKeepAlive() {
    if (keepAliveTimer) clearInterval(keepAliveTimer);
    keepAliveTimer = null;
  }

  let pwaBooted = false;
  function bootPwa() {
    if (pwaBooted) return;
    pwaBooted = true;

    authCard.hidden = true;
    heroCard.hidden = false;
    knockBtn.disabled = false;

    document.addEventListener("visibilitychange", () => {
      if (document.hidden) {
        stopKeepAlive();
      } else {
        // Resume keep-alive only if user has knocked this session
        if (keepAliveActive) startKeepAlive();
        refreshActive();
        refreshState();
        refreshStats();
      }
    });

    setInterval(() => { refreshState(); refreshActive(); }, STATE_REFRESH_MS);

    refreshState();
    refreshActive();
    refreshStats();
  }

  function showAuthCard(mode) {
    heroCard.hidden = true;
    authCard.hidden = false;
    authRegisterBtn.hidden = true;
    authLoginBtn.hidden = true;
    authLocked.hidden = true;
    if (mode === "register") {
      authRegisterBtn.hidden = false;
      authDesc.textContent = t("knock.auth_desc_register");
    } else if (mode === "login") {
      authLoginBtn.hidden = false;
      authDesc.textContent = t("knock.auth_desc_login");
    } else {
      authLocked.hidden = false;
      authDesc.textContent = t("knock.auth_desc_locked");
    }
  }

  async function doRegister() {
    if (!window.webauthnRegister) {
      showToast(t("knock.webauthn_unsupported"), "error");
      return;
    }
    try {
      const optsRes = await fetch(`${BASE}/webauthn/register/options`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
      const optsData = await optsRes.json();
      if (!optsRes.ok || !optsData.success) {
        throw new Error(optsData.error || "register options failed");
      }
      const attestation = await window.webauthnRegister(optsData.options);
      const verifyRes = await fetch(`${BASE}/webauthn/register/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ response: attestation }),
      });
      const verifyData = await verifyRes.json();
      if (!verifyRes.ok || !verifyData.success) {
        throw new Error(verifyData.error || "register verify failed");
      }
      showToast(t("knock.auth_registered"), "success");
      bootPwa();
    } catch (err) {
      showToast(err.message || String(err), "error");
    }
  }

  // Auth endpoint prefix: portal uses /portal/webauthn/*, token mode uses /u/:token/webauthn/*
  const AUTH_BASE = PORTAL_MODE ? "/portal" : BASE;

  async function doLogin() {
    if (!window.webauthnAuthenticate) {
      showToast(t("knock.webauthn_unsupported"), "error");
      return;
    }
    try {
      const optsRes = await fetch(`${AUTH_BASE}/webauthn/authenticate/options`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
      const optsData = await optsRes.json();
      if (!optsRes.ok || !optsData.success) {
        throw new Error(optsData.error || "login options failed");
      }
      const assertion = await window.webauthnAuthenticate(optsData.options);
      const verifyRes = await fetch(`${AUTH_BASE}/webauthn/authenticate/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ response: assertion }),
      });
      const verifyData = await verifyRes.json();
      if (!verifyRes.ok || !verifyData.success) {
        throw new Error(verifyData.error || "login verify failed");
      }
      // Portal mode: redirect to /my after login (server sets cookie)
      if (PORTAL_MODE) {
        window.location.href = "/my";
        return;
      }
      showToast(t("knock.auth_signed_in"), "success");
      bootPwa();
    } catch (err) {
      showToast(err.message || String(err), "error");
    }
  }

  authRegisterBtn.addEventListener("click", doRegister);
  authLoginBtn.addEventListener("click", doLogin);

  async function startBoot() {
    // Portal login page: show only passkey login button, no PWA content
    if (PORTAL_LOGIN) {
      showAuthCard("login");
      return;
    }

    if (!REQUIRE_PASSKEY) {
      bootPwa();
      return;
    }
    // Ask the server whether we already have a valid session. /state
    // also reports whether a fresh registration window is open, so we can
    // decide between "register" / "login" / "locked" modes.
    try {
      const res = await fetch(`${BASE}/state`);
      const data = await res.json();
      if (!data.success) throw new Error(data.error || "state failed");
      const auth = data.auth || {};
      if (auth.sessionValid) {
        bootPwa();
        return;
      }
      if (auth.hasCredentials) {
        showAuthCard("login");
      } else if (auth.registrationOpen) {
        showAuthCard("register");
      } else {
        showAuthCard("locked");
      }
    } catch (err) {
      if (PORTAL_MODE) {
        // Portal session expired — redirect to login
        window.location.href = "/";
        return;
      }
      showToast(err.message || String(err), "error");
      showAuthCard("locked");
    }
  }

  startBoot();

  // Register service worker (for installability — not required for knock)
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register(`${BASE}/sw.js`, { scope: BASE }).catch(() => {});
  }
})();
