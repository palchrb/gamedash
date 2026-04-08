# gamedash

A PWA + API for managing one or more game servers (Minecraft and friends)
behind a per-child knock-link with smart firewall management.

Originally a single-Minecraft dashboard, now generalized to:

- **Multi-game**: 1+ Minecraft instances, Among Us / Impostor, or any
  container — driven by a single `services.json` config.
- **Per-child knock links**: every kid gets a personal `/u/<token>` URL
  that they install as a PWA on their phone, tablet or desktop. Tapping
  the icon opens the firewall for the household IP for 24 h. One active IP
  per user — a new IP automatically swaps out the old one.
- **Smart-revoke safety**: a knock from a different network never silently
  cuts off an active game session. The server queries kernel state
  (`ss` / `conntrack`) before any IP swap and forces an explicit
  user-confirmation dialog if someone is still playing.
- **Anchor-IP guard** in the PWA: if the device's current public IP
  doesn't match the last successful knock, the PWA shows a warning before
  knocking.
- **Live state + playtime stats**: "Who is playing now" panel and
  per-user real playtime accumulated from actual connection time.
- **i18n** via flat JSON locales, controlled by `DEFAULT_LOCALE` env.
- **Passkey auth** on the admin UI (Phase 1, coming next), with configurable
  session TTL and glide re-auth.

## Stack

- **Backend:** Node 20 + TypeScript (strict), Express 4, Zod, pino, vitest.
- **Frontend:** vanilla PWA + admin dashboard (no build step).
- **Persistence:** JSON files in `/mcdata/` with atomic writes, per-file
  mutex, and schema validation on load. Tokens + session ids stored only
  as SHA-256 hashes.
- **Firewall:** host UFW driven via a privileged `ufw-agent` sidecar
  (`nsenter -t 1`).
- **Deploy:** Multi-stage Docker build, multi-arch (amd64/arm64) via
  GitHub Actions to `ghcr.io`.

## Quick start

```bash
git clone …
cd gamedash
# edit docker-compose.yml if needed
docker compose up -d
```

Open `http://<host>:3000` for the admin dashboard.

> Admin passkey auth is part of **Phase 1** (in-progress). Until that
> lands, port 3000 is open — only bind it to a trusted interface
> (reverse proxy, VPN, LAN) and do not expose it to the internet.

## Repository layout

```
api/
├── src/
│   ├── server.ts            bootstrap
│   ├── app.ts               express wiring
│   ├── config.ts            typed env (Zod)
│   ├── logger.ts            pino
│   ├── schemas.ts           single source of truth for JSON shapes
│   ├── lib/
│   │   ├── atomic-file.ts   atomic writes + per-file mutex + Zod load
│   │   ├── hash.ts          SHA-256 + timingSafeEqual helpers
│   │   ├── ip.ts            strict public-IPv4 validation
│   │   ├── exec.ts          typed execFile wrapper with timeouts
│   │   ├── nsenter.ts       ufw-agent sidecar wrapper
│   │   ├── rcon-pool.ts     exponential-backoff RCON connection
│   │   └── i18n.ts          t() + resolveLang()
│   ├── firewall/
│   │   ├── ufw.ts           UFW mutations via sidecar
│   │   └── connections.ts   ss + conntrack queries
│   ├── repos/               atomic JSON repositories
│   │   ├── users.ts
│   │   ├── firewall-rules.ts
│   │   ├── stats.ts
│   │   ├── admin.ts         credentials + sessions (Phase 1)
│   │   └── audit.ts         append-only JSONL
│   ├── services/
│   │   ├── types.ts         adapter interface
│   │   ├── base.ts          docker-exec lifecycle
│   │   ├── generic.ts       lifecycle only
│   │   ├── minecraft.ts     RCON + worlds + backups
│   │   └── registry.ts      loads services.json
│   ├── knock/
│   │   └── smart-revoke.ts  core knock flow + sweepExpiredRules
│   ├── stats/
│   │   └── collector.ts     60s playtime collector
│   ├── middleware/
│   │   ├── async-handler.ts
│   │   └── error-handler.ts
│   └── routes/
│       ├── i18n.ts
│       ├── services.ts
│       ├── users.ts
│       ├── firewall.ts
│       ├── stats.ts
│       └── knock-pwa.ts
├── public/                  admin dashboard (static)
├── pwa/                     knock PWA (static)
├── locales/                 i18n dictionaries
├── package.json
├── tsconfig.json
├── vitest.config.ts
└── Dockerfile               multi-stage Node 20 + TS build
```

## services.json

`services.json` MUST exist at `/mcdata/services.json`. There is no
auto-seeding — the registry fails loudly if it is missing or invalid.
See `docker-compose.yml` for a sample bind-mount, and:

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

Restart the dashboard container after editing.

## Host requirements

The dashboard drives the host firewall via a small privileged sidecar
(`ufw-agent`) that uses `nsenter -t 1` to enter the host namespaces.
The sidecar runs the *host's* binaries, so the host must have:

- `ufw` — required, the firewall itself
- `iproute2` (gives `ss`) — virtually always preinstalled
- `conntrack` — needed for UDP smart-revoke and UDP playtime stats.
  On Debian/Ubuntu: `sudo apt install conntrack`. The dashboard degrades
  gracefully if missing; only UDP-game session detection is lost.

## Configuration

All configuration is via environment variables (validated with Zod at
start-up). Key variables:

| Variable | Default | Purpose |
|---|---|---|
| `API_PORT` | `3000` | HTTP listen port |
| `TRUST_PROXY` | `loopback` | Value passed to Express `trust proxy` |
| `DATA_DIR` | `/mcdata` | Root for all JSON state files |
| `DEFAULT_SERVICE_ID` | `mc1` | Which service is "default" |
| `KNOCK_USER_TTL_HOURS` | `24` | How long a knock keeps a rule alive |
| `KNOCK_IGNORE_RANGES` | `100.64.0.0/10` | CIDRs to silently ignore |
| `DEFAULT_LOCALE` | `en` | UI default language |
| `LOG_LEVEL` | `info` | pino log level |
| `LOG_PRETTY` | `false` | pretty-print for local dev |
| `ADMIN_RP_ID` | `localhost` | WebAuthn relying party id (Phase 1) |
| `ADMIN_ORIGIN` | `http://localhost:3000` | WebAuthn expected origin |
| `ADMIN_SESSION_TTL_HOURS` | `12` | How long a login lasts |
| `ADMIN_REAUTH_AFTER_HOURS` | `168` | Glide re-auth deadline |
| `ADMIN_BOOTSTRAP_WINDOW_MINUTES` | `15` | First-admin registration window |
| `KNOCK_REQUIRE_PASSKEY` | `false` | Require passkey on per-user PWA (Phase 3) |

## Development

```bash
cd api
npm install
npm run dev       # tsx watch mode
npm run typecheck # tsc --noEmit
npm test          # vitest
npm run build     # tsc → dist/
npm start         # node dist/server.js
```

## Running games in separate compose files

If you'd rather not bundle every game into the dashboard's compose, create
a shared docker network on the host once:

```bash
docker network create mc-shared
```

Then declare it as `external: true` in **both** the dashboard's compose
and each game's compose. The dashboard resolves each game by its
container name (the `container` field in `services.json`), so games can
live in any compose file on the same host as long as they join
`mc-shared`.

## Roadmap

Work-in-progress rewrite on branch `claude/review-repo-structure-EOccA`:

- [x] **Phase 0**: Full TypeScript rewrite with strict typing, Zod
      validation on all JSON boundaries, atomic writes + per-file mutex,
      pino structured logging, multi-stage Docker build, vitest suite.
- [ ] **Phase 1**: Passkey (WebAuthn) auth on the admin UI with
      configurable session TTL, bootstrap window on first start,
      reverse-proxy support.
- [ ] **Phase 2**: RCON connection pool cleanup, `/api/public-ip`
      endpoint, RCON command whitelist, frontend cleanup.
- [ ] **Phase 3**: Optional passkey-gated knock PWA (env flag).
- [ ] **Phase 4**: `/healthz`, `/metrics`, graceful shutdown, audit-log
      rotation.
