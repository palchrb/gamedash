# minecraft-dashboard

A PWA + API for managing one or more game servers (Minecraft and friends)
behind a per-child knock-link with smart firewall management.

Originally a single-Minecraft dashboard for my son; now generalized to:

- **Multi-game**: 1+ Minecraft instances, Among Us / Impostor, or any
  container — driven by a single `services.json` config.
- **Per-child knock links**: every kid gets a personal `/u/<token>` URL
  that they install as a PWA on their phone, tablet or desktop. Tapping
  the icon opens the firewall for the household IP for 24h. One active IP
  per user — a new IP automatically swaps out the old one.
- **Smart-revoke safety**: a knock from a different network never silently
  cuts off an active game session. The server queries kernel state
  (`ss` / `conntrack`) before any IP swap and forces an explicit
  user-confirmation dialog if someone is still playing.
- **Anchor-IP guard** in the PWA: if the device's current public IP
  doesn't match the last successful knock, the PWA shows a warning before
  knocking — protecting against e.g. a parent's phone on 4G accidentally
  overwriting the home IP.
- **Live state + playtime stats**: a "Who is playing now" panel and
  per-user playtime accumulated from real connection time (not just
  whitelist time).
- **i18n** via flat JSON locales, controlled by `DEFAULT_LOCALE` env.
  v1 ships English only — drop a new file in `api/locales/` to add
  another language without touching code.

## Quick start

```bash
git clone …
cd minecraft-dashboard
cp .env.example .env   # if you keep one; otherwise edit compose directly
docker compose up -d
```

Open `http://<host>:3000` for the admin dashboard. Add a user in the
"Users" panel — you'll get a `/u/<token>` link to send to your kid.
They open it, tap "Install as app" (Chrome/Edge/Safari), and the icon
on their home screen / desktop becomes their one-tap "Play" button.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  api/                                                    │
│   ├─ server.js          Express routes + boot           │
│   ├─ registry.js        Loads services.json             │
│   ├─ services/          Per-game adapters               │
│   │   ├─ base.js         Lifecycle interface            │
│   │   ├─ minecraft.js    RCON + worlds + backups        │
│   │   └─ generic.js      Lifecycle-only fallback        │
│   ├─ users.js           CRUD + knock + smart-revoke     │
│   ├─ firewall.js        Generalized UFW operations     │
│   ├─ connections.js     ss / conntrack (kernel state)   │
│   ├─ stats.js           60s playtime collector          │
│   ├─ i18n.js            t() helper                      │
│   └─ locales/           Flat JSON dictionaries          │
│       └─ en.json                                        │
│                                                          │
│  api/public/            Admin dashboard (legacy UI)     │
│  api/public/u/          Personal knock PWA              │
└─────────────────────────────────────────────────────────┘
```

### services.json

Auto-generated on first boot from legacy `MC_*` env vars. To add another
service, add a block:

```jsonc
{
  "services": [
    {
      "id": "mc1",
      "name": "Minecraft",
      "type": "minecraft",
      "container": "mc1",
      "rcon": { "host": "mc", "port": 25575, "passwordEnv": "RCON_PASSWORD" },
      "ports": [
        { "port": "25565", "proto": "tcp" },
        { "port": "19132", "proto": "udp" }
      ],
      "dataDir": "/mcdata",
      "logFile": "/mcdata/logs/latest.log"
    },
    {
      "id": "impostor",
      "name": "Among Us",
      "type": "generic",
      "container": "impostor",
      "ports": [
        { "port": "22023", "proto": "tcp" },
        { "port": "22023", "proto": "udp" }
      ]
    }
  ]
}
```

Restart the dashboard container to pick up changes.

## Running games in separate compose files

If you'd rather not bundle every game into the dashboard's compose, create
a shared docker network on the host once:

```bash
docker network create mc-shared
```

Then declare it as `external: true` in **both** the dashboard's compose
and each game's compose:

```yaml
networks:
  mcnet:
    external: true
    name: mc-shared
```

The dashboard resolves each game by its container name (the `container`
field in `services.json`), so games can live in any compose file on the
same host as long as they join `mc-shared`.

## Host requirements

The dashboard drives the host firewall via a small privileged sidecar
(`ufw-agent`) that uses `nsenter -t 1` to enter the host namespaces.
The sidecar runs the *host's* binaries, so the host must have:

- `ufw` — required, the firewall itself
- `iproute2` (gives `ss`) — virtually always preinstalled
- `conntrack` — needed for UDP smart-revoke and UDP playtime stats.
  On Debian/Ubuntu: `sudo apt install conntrack`. The dashboard degrades
  gracefully if missing; only UDP-game session detection is lost.

## Multi-language

Default language is set via the `DEFAULT_LOCALE` env var (default `en`).
v1 ships only English. To add another language:

1. Copy `api/locales/en.json` to e.g. `api/locales/nb.json`.
2. Translate the values.
3. Set `DEFAULT_LOCALE=nb` in compose and restart.

Missing keys fall back to `en.json` so a half-translated file is safe.

## Per-user knock links

Add a user from the admin dashboard's "Users" panel. You'll get back a
URL like `https://your-host/u/<random32bytes>`. Send it to your kid.
On their device:

1. Open the URL in Chrome / Edge / Brave (Android, desktop) or Safari (iOS).
2. Tap "Install app" / "Add to Home Screen".
3. The icon now lives on their home screen / Start menu / Launchpad.
4. **Tapping the icon = auto-knock for 24h.** That's it. Same URL works
   for siblings on the same household IP.

The PWA also auto-renews while it's open in the foreground (every 10
minutes), so a kid who keeps it open next to their console gets a fresh
expiry without doing anything.

### Anchor-IP guard

The PWA stores the last successful IP locally. Before any new knock, it
fetches the device's current public IP (via `api.ipify.org` and fallbacks)
and compares. If they differ, you get a blocking dialog explaining that
continuing will swap the home IP for the current network. This protects
against a parent's phone on 4G at work accidentally swapping out the home
IP — a real risk because the system enforces "one active IP per user".

### Smart-revoke

Even if the client guard is bypassed, the server independently checks
`ss` / `conntrack` for live game traffic from the existing IP before
allowing any IP swap. If a session is live, the server returns
`409 {requireConfirm: "active_session"}` and the PWA shows a confirmation
dialog. Only an explicit user `?force=true` actually overrides.

## Live sessions and playtime stats

`/api/active-sessions` and `/api/stats` (admin) plus `/u/<token>/stats`
(per user) expose:

- Who is currently connected to which game (with player names for MC).
- Per-user real playtime (not whitelist time), accumulated every 60s
  from `ss` / `conntrack` snapshots.
- Daily / weekly / total per service.

## Legacy single-MC behavior

All the old `/api/status`, `/api/start`, `/api/whitelist/*`, etc. routes
still work — they're just thin shims that call the default service
adapter (`DEFAULT_SERVICE_ID`, defaulting to `mc1`). The original
admin dashboard still works without any client-side changes; only the
new "Users", "Active sessions" and "Stats" panels are additive.
