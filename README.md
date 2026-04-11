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
cp .env.example .env                       # then edit
mkdir -p data
cp services.json.example data/services.json  # then edit for your setup
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

## Host permissions

The gamedash image runs as the non-root `node` user (uid 1000) inside
the container. There's one install-time footgun: bind-mounted game
server data directories must be writable by uid 1000, or backups and
world-switching will fail with `EACCES` at click-time.

### Docker socket — handled by the proxy sidecar

Gamedash needs to talk to the host docker daemon for
start/stop/restart/inspect/logs, but it never mounts
`/var/run/docker.sock` directly. Instead the shipped
`docker-compose.yml` runs a `docker-proxy` sidecar
(`tecnativa/docker-socket-proxy`) that whitelists only
`GET /containers/*` and POST on the same paths. Everything else —
`exec`, `build`, `pull`, `volume create`, `secrets`, `networks`,
swarm — is blocked. So even if gamedash is compromised, an attacker
can't pivot to full root-on-host through the socket.

The dashboard reaches the proxy via `DOCKER_HOST=tcp://docker-proxy:2375`
(set in `docker-compose.yml` — you don't need to touch `.env`).

### Game server data directories

The host directory you bind-mount to `/mc-data` (or whatever your
`dataDir` is) must be writable by uid 1000 — that's where gamedash
writes backups and does world switching. If the Minecraft server was
started with a different uid, the mount will be read-only from
gamedash's point of view and you'll see `EACCES: permission denied,
mkdir '/mc-data/backups/...'`.

The simplest fix is to chown the host directory so both gamedash and
the MC container can write it. `itzg/minecraft-server` defaults to uid
1000 too, so in the common case this is a no-op:

```bash
sudo chown -R 1000:1000 /path/to/mc-server/data
```

If your MC container runs as a different uid, either (a) align them by
passing `UID=1000` / `GID=1000` to the MC container, or (b) give both
uids access via a shared group and `chmod g+rwX -R` the directory.

## Configuration

### `services.json` (required)

`services.json` lives at `./data/services.json` (bind-mounted to
`/data/services.json` in the container). The registry fails loudly if
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
        { "port": "19132", "proto": "udp" },
        { "port": "24454", "proto": "udp" }
      ],
      "mapUrl": "https://map.example.com",
      "dataDir": "/mc-data",
      "logFile": "/mc-data/logs/latest.log"
    },
    {
      "id": "impostor",
      "name": "Among Us",
      "type": "generic",
      "container": "impostor",
      "ports": [
        { "port": "22023", "proto": "udp" }
      ]
    },
    {
      "id": "terraria",
      "name": "Terraria",
      "type": "generic",
      "container": "terraria",
      "ports": [
        { "port": "7777", "proto": "tcp" }
      ]
    }
  ]
}
```

Game containers do **not** need to live in the same `docker-compose.yml`
as the dashboard. Gamedash reaches them via `docker exec <container>`,
which works against any container on the host regardless of which
compose stack started it. Just make sure the `container` name in
`services.json` matches the actual container name.

For Minecraft services with `type: "minecraft"`, `dataDir` must point
to the MC server's data directory **as seen inside the gamedash
container**. Bind-mount it in `docker-compose.yml`:

```yaml
volumes:
  - ./data:/data                            # gamedash state
  - /path/to/mc-server/data:/mc-data        # minecraft data (backup, worlds, logs)
```

Then set `"dataDir": "/mc-data"` in `services.json`. Without this
mount the dashboard can still start/stop the container and send RCON
commands, but backup, world-switching, and log viewing won't work.

The optional `mapUrl` field adds a "View world map" link in the child's
knock PWA. The URL should point to wherever you host your map viewer
(e.g. BlueMap proxied through Caddy — see the reverse proxy section
below).

Restart the dashboard container after editing.

### Environment variables

All env vars are validated with Zod at start-up — invalid input crashes
with a clear error rather than a silent misconfiguration.

| Variable | Default | Purpose |
|---|---|---|
| `API_PORT` | `3000` | HTTP listen port |
| `TRUST_PROXY` | `loopback` | Value passed to Express `trust proxy` — set to your proxy IP(s) when terminating TLS upstream |
| `DATA_DIR` | `/data` | Root for all JSON state files |
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
| `UFW_SIDECAR_URL` | `http://ufw-sidecar:9090` | URL of the UFW sidecar API |
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

## Reverse proxy (Caddy)

Exposing the dashboard on the public internet should always go through
a reverse proxy that terminates TLS. Caddy is the easiest option —
here's a minimal `Caddyfile` that fronts a gamedash container running
on the same host:

```caddyfile
dash.example.com {
    encode zstd gzip
    reverse_proxy localhost:3000
}
```

That's all Caddy needs — it will obtain and renew a Let's Encrypt
certificate automatically, and it sets `X-Forwarded-For` /
`X-Forwarded-Proto` on every upstream request.

On the gamedash side you then need three env vars in `.env` so
WebAuthn and the IP allow-list line up with what the browser actually
sees:

```bash
ADMIN_RP_ID=dash.example.com
ADMIN_ORIGIN=https://dash.example.com
TRUST_PROXY=loopback
```

- **`ADMIN_RP_ID`** — the bare hostname, no scheme, no port. WebAuthn
  refuses to register if this doesn't match the address bar exactly.
- **`ADMIN_ORIGIN`** — the full URL as the browser sees it. `:443` is
  implied for HTTPS, so do not add it.
- **`TRUST_PROXY`** — `loopback` is correct when Caddy runs on the
  same host and proxies over `127.0.0.1`. If Caddy runs in its own
  container on the Docker bridge, set this to the Caddy container's
  IP, a CIDR like `172.16.0.0/12`, or `uniquelocal`. Without a
  correct value, Express sees the proxy's IP and the per-child knock
  will allow-list the wrong address.

Restart the `dashboard` container after changing any of these. For a
Caddy-in-Docker setup, add a `caddy` service to `docker-compose.yml`,
put it on the same `mcnet` network as `dashboard`, and point
`reverse_proxy` at `dashboard:3000` instead of `localhost:3000`.

### Keeping the admin UI off the public internet

The API listens on a single port and serves three distinct URL
surfaces:

| Prefix        | Who should reach it                                    |
| ------------- | ------------------------------------------------------ |
| `/`, `/api/*` | Admin UI + admin API (passkey-gated, but still admin)  |
| `/u/:token/*` | Per-child knock PWA (self-contained; inlines its i18n) |
| `/healthz`    | Liveness probe                                         |

Because the knock PWA lives entirely under `/u/*`, it is easy to
expose only that prefix on the public vhost and keep the admin UI on
a separate hostname that is only reachable over Tailscale (or any
other private network).

```caddyfile
# Public vhost: only the per-child knock PWAs are reachable from the
# open internet. Everything else returns 404.
dash.example.com {
    encode zstd gzip

    @knock path /u/*
    handle @knock {
        reverse_proxy localhost:3000
    }

    handle /healthz {
        reverse_proxy localhost:3000
    }

    handle {
        respond "Not found" 404
    }
}

# Admin vhost: only bound to the Tailscale interface, so it is only
# reachable from machines on your tailnet. Caddy will request a
# certificate from Tailscale's built-in CA automatically when the
# hostname ends in .ts.net.
dash.tailnet-name.ts.net {
    bind tailscale0
    reverse_proxy localhost:3000
}
```

A few notes on this layout:

- **`ADMIN_RP_ID` / `ADMIN_ORIGIN` must match the admin vhost**, not
  the public one. Set them to `dash.tailnet-name.ts.net` and
  `https://dash.tailnet-name.ts.net`. WebAuthn will refuse to
  register a passkey otherwise.
- The public vhost never serves a login page, so
  `dash.example.com/` returns 404 — that's intentional. Anyone
  scanning for an admin UI on the public hostname finds nothing to
  attack.
- The `bind tailscale0` line restricts Caddy's listener to the
  Tailscale interface. Adjust the interface name to match your host
  (`tailscale0` on Linux, `utun*` on macOS). An alternative is to
  skip `bind` entirely and rely on a host firewall or `iptables`
  rule that only allows the tailnet CIDR to reach port 443.
- If you want the admin UI to reach the API via the same hostname as
  the browser, keep `ADMIN_RP_ID` / `ADMIN_ORIGIN` pointed at the
  admin vhost. The public vhost doesn't serve `/api/*` at all in
  this layout, so the dashboard simply isn't reachable from it.

If you don't care about public exposure at all and just want the
whole thing on your tailnet, drop the public vhost and keep only the
`dash.tailnet-name.ts.net` block.

## License

See [LICENSE](LICENSE).
