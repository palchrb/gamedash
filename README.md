# gamedash

Self-hosted admin + per-child PWA for running one or more game servers
(Minecraft and friends) behind an IP allow-list. Kids get a personal
`/u/<token>` link they install as a PWA; tapping it opens the firewall
for the household's current IP, live kernel state prevents cutting off
an active game session, and per-user playtime is tracked automatically.

Admin UI is gated by a WebAuthn passkey. The per-child PWA is gated by
the URL token, and can additionally require a passkey if you set
`KNOCK_REQUIRE_PASSKEY=true`.

## Requirements

- Linux host with Docker + `docker compose`
- Host packages used by the sidecar via `nsenter`:
  - `ufw` *(required — the firewall itself)*
  - `iproute2` for `ss` *(preinstalled on essentially every distro)*
  - `conntrack` *(optional; needed only for UDP smart-revoke and UDP
    playtime — `sudo apt install conntrack` on Debian/Ubuntu)*
- A browser/device that supports passkeys (any modern iOS/Android/desktop)

## Quick start

```bash
git clone https://github.com/palchrb/gamedash.git
cd gamedash
cp .env.example .env      # then edit — at minimum set RCON_PASSWORD
mkdir -p data
# drop your services.json in place — see "Configuration" below
docker compose up -d
```

Then:

1. Open `http://<host>:3000`. On first start the admin UI shows a
   **15-minute bootstrap window** during which you can create the first
   admin and register a passkey. The window closes automatically after
   that; restart the container to re-open it if you miss it.
2. Use the admin UI to add a child (**Users → Add user**). The plaintext
   knock link is shown once, right after creation — copy it and share it
   with that child over a secure channel. It cannot be recovered later,
   only rotated.
3. The child opens the link on their device and installs it as a PWA.
   Tapping the big button auto-knocks the household IP into the firewall
   and starts the 24-hour timer.

> **Do not expose port 3000 to the public internet without a reverse
> proxy**. The admin UI is passkey-gated, but TLS termination and
> rate-limiting are expected to come from an upstream proxy.

## Configuration

### `services.json` (required)

`services.json` lives at `./data/services.json` (bind-mounted to
`/mcdata/services.json` in the container). The registry fails loudly if
it's missing.

```jsonc
{
  "services": [
    {
      "id": "mc1",
      "name": "Minecraft",
      "type": "minecraft",
      "container": "mc1",
      "rcon": {
        "host": "mc",
        "port": 25575,
        "passwordEnv": "RCON_PASSWORD"
      },
      "ports": [
        { "port": "25565", "proto": "tcp" },
        { "port": "19132", "proto": "udp" }
      ],
      "dataDir": "/mcdata",
      "logFile": "/mcdata/logs/latest.log"
    }
  ]
}
```

Restart the dashboard container after editing.

### Environment variables

All env vars are validated with Zod at start-up — invalid input crashes
with a clear error rather than a silent misconfiguration.

| Variable | Default | Purpose |
|---|---|---|
| `API_PORT` | `3000` | HTTP listen port |
| `TRUST_PROXY` | `loopback` | Value passed to Express `trust proxy` — set to your proxy IP(s) when terminating TLS upstream |
| `DATA_DIR` | `/mcdata` | Root for all JSON state files |
| `DEFAULT_SERVICE_ID` | `mc1` | Which service is "default" in the UI |
| `KNOCK_USER_TTL_HOURS` | `24` | How long a knock keeps a rule alive |
| `KNOCK_IGNORE_RANGES` | `100.64.0.0/10` | CIDRs to silently ignore (e.g. CGNAT) |
| `DEFAULT_LOCALE` | `en` | UI default language |
| `LOG_LEVEL` | `info` | pino log level |
| `LOG_PRETTY` | `false` | Pretty-print logs (local dev) |
| `ADMIN_RP_ID` | `localhost` | WebAuthn relying-party ID — must be the bare hostname |
| `ADMIN_ORIGIN` | `http://localhost:3000` | WebAuthn expected origin — must match scheme + host + port the browser sees |
| `ADMIN_SESSION_TTL_HOURS` | `12` | Sliding session lifetime |
| `ADMIN_REAUTH_AFTER_HOURS` | `168` | Hard re-auth deadline (forces passkey again) |
| `ADMIN_BOOTSTRAP_WINDOW_MINUTES` | `15` | First-admin registration window |
| `KNOCK_REQUIRE_PASSKEY` | `false` | Also require a passkey on the per-child PWA |
| `KNOCK_PASSKEY_REAUTH_HOURS` | `720` | Knock session TTL when passkey is required |
| `KNOCK_REGISTRATION_TTL_HOURS` | `24` | Per-user passkey enrolment window |
| `AUDIT_LOG_MAX_BYTES` | `10485760` | Audit log rotation threshold |
| `AUDIT_LOG_MAX_FILES` | `5` | Audit log generations to keep |

When running behind HTTPS, set **both** `ADMIN_RP_ID` (bare hostname,
e.g. `dash.example.com`) and `ADMIN_ORIGIN` (full URL,
e.g. `https://dash.example.com`). WebAuthn refuses to register if these
don't match the browser's address bar exactly.

## Operational endpoints

Public (no auth, safe to probe from an orchestrator):

- `GET /healthz` — liveness
- `GET /readyz` — readiness (503 if the registry or stores are not reachable)
- `GET /metrics` — Prometheus text format

## Development

```bash
cd api
npm install
npm run dev        # tsx watch
npm run typecheck  # tsc --noEmit
npm test           # vitest
npm run build      # tsc → dist/
```

The project is Node 22 + TypeScript strict, Express 4, Zod, pino,
vitest. State lives in JSON files under `DATA_DIR` with atomic writes,
per-file mutex, and schema validation on load. Tokens + session IDs are
only ever stored as SHA-256 hashes.

## License

See [LICENSE](LICENSE).
