/**
 * Shared "Who is playing now" renderer — used by BOTH the player PWA
 * (pwa/u.js) and the admin Play tab (public/app.js).
 *
 * The admin Play tab is meant to be identical to the player card. It
 * used to be a hand-copied duplicate, and the copy drifted (it lost the
 * per-service player counts, player names and Among Us lobby list).
 * Rendering lives here now so the two can't drift apart again.
 *
 * Served as /admin/play-shared.js, /u/:token/play-shared.js and
 * /my/play-shared.js. Exposes window.GamedashPlay.
 *
 * Input shape (both /u/:token/active and /admin/api/active-sessions):
 *   { sessions: [{ name, ips, suspended?, services: [{id, name, connected, playerNames}] }],
 *     games: { [serviceId]: [{code, host, map, playerCount, maxPlayers, players, isPublic, state}] } }
 */
(function () {
  "use strict";

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function renderServiceSummary(svcMap) {
    return Object.values(svcMap)
      .filter((sv) => sv.players.length > 0 || sv.connected > 0)
      .map((sv) => {
        const count = sv.players.length || sv.connected;
        const names = sv.players.length > 0
          ? `<span class="svc-players">${sv.players.map(esc).join(", ")}</span>`
          : "";
        return `<li class="svc-summary-item">
          <span><span class="dot green"></span><strong>${esc(sv.name)}</strong></span>
          <span>${count} online</span>
          ${names ? `<div class="svc-summary-names">${names}</div>` : ""}
        </li>`;
      })
      .join("");
  }

  function renderGames(gamesByService, serviceNames) {
    return Object.entries(gamesByService || {})
      .flatMap(([sid, games]) => {
        if (!Array.isArray(games) || games.length === 0) return [];
        const svcName = serviceNames[sid] || sid;
        const items = games
          .map((g) => {
            const code = String(g.code || "").toUpperCase();
            const host = g.host ? esc(g.host) : "";
            const playerCount = typeof g.playerCount === "number" ? g.playerCount : (g.players || []).length;
            const max = g.maxPlayers ? `/${g.maxPlayers}` : "";
            const visibility = g.isPublic
              ? '<span class="game-badge game-public">public</span>'
              : '<span class="game-badge game-private">private</span>';
            const state = g.state && g.state !== "NotStarted"
              ? `<span class="game-badge game-state">${esc(String(g.state).toLowerCase())}</span>`
              : "";
            const map = g.map ? `<span class="game-map">${esc(g.map)}</span>` : "";
            const players = (g.players || []).length > 0
              ? `<div class="svc-summary-names">${g.players.map(esc).join(", ")}</div>`
              : "";
            return `<li class="game-item" data-game-code="${esc(code)}">
              <div class="game-row">
                <span class="game-code" title="Tap to copy">${esc(code)}</span>
                ${map}
                <span class="game-players">${playerCount}${max}</span>
                ${visibility}
                ${state}
              </div>
              ${host ? `<div class="game-meta muted">Host: ${host}</div>` : ""}
              ${players}
            </li>`;
          })
          .join("");
        return [
          `<div class="svc-games-group">
             <h3 class="svc-games-title">${esc(svcName)} · ${games.length} active</h3>
             <ul class="svc-games-list">${items}</ul>
           </div>`,
        ];
      })
      .join("");
  }

  function renderUserRows(sessions, t) {
    return sessions
      .map((s) => {
        const ips = Array.isArray(s.ips) ? s.ips : (s.ip ? [s.ip] : []);
        const playing = (s.services || []).find((sv) => sv.connected);
        let dot = "gray";
        let txt = t("active.idle_unallowed");
        if (s.suspended) {
          txt = t("directory.suspended");
        } else if (playing) {
          dot = "green";
          txt = t("active.connected", { service: playing.name });
        } else if (ips.length > 0) {
          dot = "yellow";
          txt = t("active.idle_allowed");
        }
        return `<li><span><span class="dot ${dot}"></span>${esc(s.name)}</span>
          <span class="muted">${esc(txt)}</span></li>`;
      })
      .join("");
  }

  /**
   * Render the active panel into `listEl`.
   * opts: { t: (key, vars) => string, toast: (msg, kind) => void }
   */
  function renderActive(listEl, data, opts) {
    const t = opts.t;
    const sessions = (data && data.sessions) || [];
    if (sessions.length === 0) {
      listEl.innerHTML = `<li class="muted">${esc(t("common.unknown"))}</li>`;
      return;
    }

    // Aggregate per-service player counts + names (RCON / AdminApi).
    const svcMap = {};
    const serviceNames = {};
    for (const s of sessions) {
      for (const sv of s.services || []) {
        serviceNames[sv.id] = serviceNames[sv.id] || sv.name;
        if (!svcMap[sv.id]) svcMap[sv.id] = { name: sv.name, players: [], connected: 0 };
        for (const p of sv.playerNames || []) {
          if (!svcMap[sv.id].players.includes(p)) svcMap[sv.id].players.push(p);
        }
        if (sv.connected) svcMap[sv.id].connected++;
      }
    }

    const svcSummary = renderServiceSummary(svcMap);
    const gamesBlock = renderGames(data.games, serviceNames);
    listEl.innerHTML =
      (svcSummary ? `<div class="svc-summary">${svcSummary}</div>` : "") +
      gamesBlock +
      ((svcSummary || gamesBlock) ? '<hr class="active-divider">' : "") +
      renderUserRows(sessions, t);

    // Tap a lobby code → copy. (Among Us has no join-by-code deep link.)
    for (const el of listEl.querySelectorAll("[data-game-code]")) {
      el.addEventListener("click", () => {
        const code = el.getAttribute("data-game-code");
        if (!code) return;
        navigator.clipboard.writeText(code).then(
          () => opts.toast(`Copied ${code}`, "success"),
          () => opts.toast(`Code: ${code}`, "info"),
        );
      });
    }
  }

  window.GamedashPlay = { renderActive };
})();
