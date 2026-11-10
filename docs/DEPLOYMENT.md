# Deployment

This document covers the Docker-based self-hosted deployment of **Eyas** on a Linux server. For the macOS standalone (no-Docker) path, see [`STANDALONE.md`](./STANDALONE.md). For local development, see [`../QUICKSTART.md`](../QUICKSTART.md).

The multi-stage Dockerfile bundles the `falcon-extras` Python sidecar by default — agentic patching, agentic IR cleanup and its playbooks, Workflows execute, identity response, tenant provisioning, and Shadow-AI hunting all light up in the compose stack with no extra steps. Compose mounts `./data:/app/data` by default so registration, runtime settings, cost log, audit log, and IR run records persist across container recreation; the MCP server (`eyas-mcp`) is built from source at the commit pinned in `versions.json` — there is no published image — so every build is reproducible.

---

## Architecture

```
                    ┌───── reverse proxy (Caddy/nginx) ────┐
internet ─ TLS ───▶ │  TLS termination, real-IP fwd        │ ──▶ 127.0.0.1:3000
                    │  optional HTTP basic auth            │
                    └──────────────────────────────────────┘
                                      │
                       ┌──────────────┴───────────────────┐
                       │  docker compose (private bridge) │
                       │  ┌─────────────┐  ┌────────────┐ │
                       │  │ app         │  │ eyas-mcp   │ │
                       │  │ Next.js +   │──│ :8000 HTTP │ │
                       │  │ falcon-     │  │ x-api-key  │ │
                       │  │ extras      │  └────────────┘ │
                       │  │ :3000       │                 │
                       │  └─────────────┘                 │
                       └──────────────────────────────────┘
```

`eyas-mcp` (built from source at the pinned commit) is **not** internet-reachable — only the `app` service can talk to it on the bridge network. Only `127.0.0.1:3000` is published to the host, so the reverse proxy is the only public ingress. The `falcon-extras` sidecar runs inside the `app` container as a stdio child — no separate port, no separate service.

---

## Prerequisites

- Linux host (Ubuntu 22.04+ tested)
- Docker Engine ≥ 24, Docker Compose v2
- Public DNS pointed at the host
- A Falcon API client with the scopes you intend to enable (see [`QUICKSTART.md`](../QUICKSTART.md) §1)
- An Anthropic API key, or a corporate gateway with `ANTHROPIC_AUTH_TOKEN` + `ANTHROPIC_BASE_URL`

---

## Bring-up

```bash
git clone git@github.com:GTStagg/project-eyas.git
cd project-eyas
```

```bash
cp .env.example .env
# edit .env -- minimum: ANTHROPIC_API_KEY, FALCON_CLIENT_ID/SECRET/BASE_URL,
#                       FALCON_MCP_API_KEY (openssl rand -hex 32),
#                       AUTH_SESSION_SECRET (openssl rand -hex 32)
chmod 600 .env

docker compose build
docker compose up -d
docker compose logs -f
```

Open `http://127.0.0.1:3000` to confirm the app is up before wiring the reverse proxy. First hit lands at `/register` to set the console password and save Anthropic + Falcon credentials to `data/eyas.db`. Registration is only served to `localhost` / `127.0.0.1`, so do it from the host before wiring the proxy, or list the proxy's host name in `EYAS_ALLOWED_HOSTS`. At runtime the database is the single source of truth — `.env` is read only for bootstrap secrets like `AUTH_SESSION_SECRET`, not for credentials.

---

## Reverse proxy: Caddy

Caddy handles TLS, HTTP→HTTPS redirect, and X-Forwarded-For with no extra config:

```caddyfile
falcon.example.com {
    encode zstd gzip
    reverse_proxy 127.0.0.1:3000
}
```

The console enforces its own login (iron-session cookie set at `/register`), so you don't need a basicauth wrapper unless you want defense in depth. Failed logins are throttled in-app: after 5 consecutive failures each attempt waits 30 s, doubling to a 15-minute cap, and a successful login resets it. By default all clients share one counter. Behind a proxy you control that sets `X-Forwarded-For` (Caddy does by default), set `EYAS_TRUST_PROXY=true` so the counter is kept per client and a remote attacker can't delay your own logins. Leave it unset when the app is reachable without the proxy, since clients could then forge the header.

## Reverse proxy: nginx

```nginx
server {
    listen 443 ssl http2;
    server_name falcon.example.com;
    ssl_certificate     /etc/letsencrypt/live/falcon.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/falcon.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;  # login throttling, see below
        proxy_set_header X-Forwarded-Proto $scheme;

        # SSE streaming — disable buffering on /api/chat and friends
        proxy_buffering off;
        proxy_read_timeout 300s;
    }
}
server {
    listen 80;
    server_name falcon.example.com;
    return 301 https://$host$request_uri;
}
```

**`X-Forwarded-For` is required for per-client login throttling** (`proxy_add_x_forwarded_for` appends the real client address, which Eyas reads from the right-most entry when `EYAS_TRUST_PROXY=true`). Login attempts are the only thing Eyas rate-limits itself; everything else relies on the upstream Anthropic and Falcon API quotas.

---

## Update workflow

```bash
cd /opt/project-eyas
git pull
docker compose build
docker compose up -d
```

Saved conversations survive a restart (chat history is written through to `data/eyas.db`, within the 72-hour idle TTL). Only a turn that is mid-stream at the moment of restart is lost, along with any approval that was pending in memory at that instant. For low-disruption updates, schedule during off-hours.

---

## Backups

Effectively all durable state lives in a single SQLite database, **`data/eyas.db`** (mode 0600). Back up that one file (plus the `.env` that holds `AUTH_SESSION_SECRET`) and you have everything:

- **`auth` table** — single-user password hash (rebuilt via `/register` if lost).
- **`settings` + `environments` tables** — Anthropic credentials, the multi-environment Falcon list, active-env pointer, per-env sanctioned-tool list. Credentials are AES-256-GCM column-encrypted (key derived from `AUTH_SESSION_SECRET`).
- **`settings_audit` table** — append-only, SQL-trigger-enforced config-mutation log (field shape only, no values).
- **`chat_sessions` table** — saved conversations + titles, resumable within the 72h idle TTL.
- **`ir_runs` + `ir_run_turns` tables** — per-IR-engagement audit records.
- **`cost_log` table** — append-only token-spend log.
- **`aidr_blocks` table** — append-only AIDR guardrail verdicts (when AIDR is configured).

> **Backup hygiene:** because the column-encryption key is derived from `AUTH_SESSION_SECRET` (in `.env`), a backup that captures **both** `data/` and `.env` defeats the at-rest encryption. Keep the DB backup and the `.env` backup in separate, access-controlled locations.

The only file-based durable artifact is `data/perf-log.jsonl` — an append-only route + MCP timing log, written only when `PERF_LOG=true`.

Mount the data directory so the DB survives container rebuilds:

```yaml
# in docker-compose.yml under the `app` service
volumes:
  - ./data:/app/data
```

A graceful restart checkpoints the WAL (`SIGTERM`/`SIGINT`/`SIGHUP` → `wal_checkpoint(TRUNCATE)`), so a backup taken after a clean stop captures every write in the main DB file.

---

## Security posture (production checklist)

- [ ] `.env` is mode 600, owned by the deploy user, not world-readable
- [ ] `AUTH_SESSION_SECRET` set (32+ chars; `openssl rand -hex 32`); first hit prompts password registration → `data/eyas.db`
- [ ] Reverse proxy enforces TLS, redirects HTTP, forwards real client IP
- [ ] Falcon API client granted the **minimum** scopes for the surfaces you actually use (see the in-app scope checklist on `/status`); every MCP-server module loads by default and capability-gates surfaces against actual scopes, so `FALCON_MCP_MODULES` only needs setting if you want to narrow further
- [ ] `OUTBOUND_WEBHOOK_URL` (if set) points at a target you control — it receives full agentic-report markdown
- [ ] Anthropic spend cap configured at the org level; `DAILY_COST_BUDGET_USD` set as a UI guardrail
- [ ] `EYAS_TRUST_PROXY=true` only if the app is reachable solely through your proxy (per-client login throttling)
- [ ] To require a gateway token instead of an API key, set `ANTHROPIC_GATEWAY_ONLY=true`. To also lock the gateway URL so it can't be changed in the app, build with `ANTHROPIC_GATEWAY_BASE_URL` set (see [`STANDALONE.md`](./STANDALONE.md#building-the-bundle)).

