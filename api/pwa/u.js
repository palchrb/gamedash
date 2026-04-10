/**
 * Personal Knock PWA — auto-knocks on launch, refreshes while open,
 * and protects against accidentally swapping out the home IP via:
 *
 *   1. Anchor-IP guard (client side): before each knock we fetch the
 *      device's current public IP and compare against `lastKnockedIp`
 *      stored in localStorage. If they differ, we show a blocking
 *      confirmation dialog instead of just swapping.
 *
 *   2. Server smart-revoke (server side): even if the client guard is
 *      bypassed, the server checks ss/conntrack for live game traffic
 *      from the existing IP. If a session is live, the server returns
 *      409 {requireConfirm: "active_session"} and we show a similar
 *      confirmation dialog before sending ?force=true.
 */

(() => {
  const init = window.__INIT__ || {};
  const I18N = window.__I18N__ || {};
  const TOKEN = init.token;
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
  async function detectPublicIp() {
    const services = [
      "https://api.ipify.org?format=json",
      "https://api64.ipify.org?format=json",
      "https://jsonip.com",
    ];
    for (const url of services) {
      try {
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 4000);
        const res = await fetch(url, { signal: ctrl.signal });
        clearTimeout(timer);
        const data = await res.json();
        if (data.ip) return data.ip;
      } catch { /* try next */ }
    }
    return null;
  }

  // ---- Knock --------------------------------------------------------------
  async function knock(serviceIds, { force = false, skipAnchorCheck = false } = {}) {
    const state = loadState();

    // Anchor-IP guard: if we have a previous IP, compare with current
    if (!force && !skipAnchorCheck && state.lastKnockedIp) {
      const currentIp = await detectPublicIp();
      if (currentIp && currentIp !== state.lastKnockedIp) {
        const ok = await showDialog(
          t("knock.different_network_title"),
          t("knock.different_network_body", {
            oldIp: state.lastKnockedIp,
            newIp: currentIp,
          }),
        );
        if (!ok) return { aborted: true };
      }
    }

    let res, data;
    try {
      res = await fetch(
        `/u/${TOKEN}/knock${force ? "?force=true" : ""}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ services: serviceIds || "all" }),
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
      // IP is in an ignored range (CGNAT/Tailscale) — no firewall rule
      // needed. Show success without storing anchor-IP (it would be
      // meaningless and break the guard on the next visit).
      showToast(t("knock.success"), "success");
      refreshState();
      refreshActive();
      refreshStats();
      return data;
    }

    saveState({ lastKnockedIp: data.ip, lastKnockAt: new Date().toISOString() });
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
      const res = await fetch(`/u/${TOKEN}/state`);
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

      // Per-service list (+ inline map links + connection info)
      if (SERVICES.length > 1) {
        servicesCard.hidden = false;
        servicesList.innerHTML = SERVICES.map(
          (s) =>
            `<li><div class="li-info"><span>${escapeHtml(s.name)}</span>` +
            `<div class="connect-row">${connectInfo(s)}</div></div>` +
            `<span class="li-actions">` +
            (s.mapUrl
              ? `<a class="map-link-inline" href="${escapeAttr(s.mapUrl)}" target="_blank" rel="noopener">` +
                `<span class="map-icon">&#x1f5fa;&#xfe0e;</span> ${t("btn.view_map")}</a> `
              : "") +
            `<button class="btn btn-small" data-knock-one="${escapeAttr(s.id)}">` +
            `${t("btn.knock_one", { service: s.name })}</button></span></li>`,
        ).join("");
        for (const btn of servicesList.querySelectorAll("[data-knock-one]")) {
          btn.onclick = () => knock([btn.dataset.knockOne]);
        }
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
    } catch (err) {
      console.error("refreshState failed:", err);
    }
  }

  // ---- Active sessions panel -------------------------------------------
  async function refreshActive() {
    try {
      const res = await fetch("/api/active-sessions");
      const data = await res.json();
      if (!data.success) return;
      if (data.sessions.length === 0) {
        activeList.innerHTML = `<li class="muted">${t("common.unknown")}</li>`;
        return;
      }
      activeList.innerHTML = data.sessions
        .map((s) => {
          const playing = s.services.find((sv) => sv.connected);
          const allowed = !!s.ip;
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
    } catch (err) {
      console.error("refreshActive failed:", err);
    }
  }

  // ---- Stats panel ------------------------------------------------------
  async function refreshStats() {
    try {
      const res = await fetch(`/u/${TOKEN}/stats`);
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

  // ---- Wire up ----------------------------------------------------------
  knockBtn.addEventListener("click", () => knock("all"));
  revokeBtn.addEventListener("click", async () => {
    if (!confirm(t("users.revoke_confirm", { name: USER.name }))) return;
    try {
      await fetch(`/u/${TOKEN}/revoke`, { method: "POST" });
      saveState({ lastKnockedIp: null });
      refreshState();
      showToast("Revoked", "success");
    } catch (err) {
      showToast(err.message, "error");
    }
  });

  // ---- Auth (Phase 3 optional passkey gate) ----------------------------
  let keepAliveTimer = null;

  function startKeepAlive() {
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

    // Fire knock immediately on first load
    knock("all").catch(() => {});

    startKeepAlive();

    document.addEventListener("visibilitychange", () => {
      if (document.hidden) {
        stopKeepAlive();
      } else {
        knock("all").catch(() => {});
        startKeepAlive();
        refreshActive();
        refreshState();
        refreshStats();
      }
    });

    setInterval(refreshState, STATE_REFRESH_MS);
    setInterval(refreshActive, STATE_REFRESH_MS);

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
      const optsRes = await fetch(`/u/${TOKEN}/webauthn/register/options`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
      const optsData = await optsRes.json();
      if (!optsRes.ok || !optsData.success) {
        throw new Error(optsData.error || "register options failed");
      }
      const attestation = await window.webauthnRegister(optsData.options);
      const verifyRes = await fetch(`/u/${TOKEN}/webauthn/register/verify`, {
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

  async function doLogin() {
    if (!window.webauthnAuthenticate) {
      showToast(t("knock.webauthn_unsupported"), "error");
      return;
    }
    try {
      const optsRes = await fetch(`/u/${TOKEN}/webauthn/authenticate/options`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
      const optsData = await optsRes.json();
      if (!optsRes.ok || !optsData.success) {
        throw new Error(optsData.error || "login options failed");
      }
      const assertion = await window.webauthnAuthenticate(optsData.options);
      const verifyRes = await fetch(`/u/${TOKEN}/webauthn/authenticate/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ response: assertion }),
      });
      const verifyData = await verifyRes.json();
      if (!verifyRes.ok || !verifyData.success) {
        throw new Error(verifyData.error || "login verify failed");
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
    if (!REQUIRE_PASSKEY) {
      bootPwa();
      return;
    }
    // Ask the server whether we already have a valid knock session. /state
    // also reports whether a fresh registration window is open, so we can
    // decide between "register" / "login" / "locked" modes.
    try {
      const res = await fetch(`/u/${TOKEN}/state`);
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
      showToast(err.message || String(err), "error");
      showAuthCard("locked");
    }
  }

  startBoot();

  // Register service worker (for installability — not required for knock)
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register(`/u/${TOKEN}/sw.js`, { scope: `/u/${TOKEN}` }).catch(() => {});
  }
})();
