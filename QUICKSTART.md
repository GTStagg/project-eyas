# Quickstart

Bring up **Eyas** — the agentic console for CrowdStrike Falcon — from source.

- **Local dev server** (start here) — compile and run from a checkout, with hot reload. The app spawns the MCP server ([`eyas-mcp`](https://github.com/GTStagg/eyas-mcp)) and the `falcon-extras` Python sidecar itself, so there is nothing else to run.
- **Standalone macOS bundle** — once the dev server works, `./make-dist.sh` packages it for a Mac that has no developer tooling. See [`docs/STANDALONE.md`](./docs/STANDALONE.md).
- **Docker Compose** — builds the app and `eyas-mcp` from source; see [step 8](#8-docker).

---

## 0. Prerequisites

- **macOS or Linux**, with **git**.
- **Node 22+** (22, 24 and 26 are supported).
- **Python 3.11+** (3.12 recommended) with a working `python3 -m venv`.
- **[uv](https://docs.astral.sh/uv/)** — `brew install uv` (or `curl -LsSf https://astral.sh/uv/install.sh | sh`). The dev server uses `uvx` to build and run `eyas-mcp` at the commit pinned in `versions.json`.
- **Network access to GitHub.** The MCP server ([`GTStagg/eyas-mcp`](https://github.com/GTStagg/eyas-mcp)) is fetched over HTTPS at the commit pinned in `versions.json`.
- A **CrowdStrike Falcon API client** — see step 1.
- An **Anthropic API key** from [console.anthropic.com](https://console.anthropic.com/), or an Anthropic-compatible gateway URL + token.

---

## 1. Create a Falcon API client

In the Falcon console: **Support and resources → API clients and keys → Create API client.**

Grant the scopes for the surfaces you want. Eyas gates every surface on what the client actually has — a missing scope hides that surface and shows a "scope pending" banner instead of an error — and `/config` shows a scope checklist mapping each scope to what it unlocks. A reasonable starting set:

| Scope | Why |
|---|---|
| `Alerts:read` | Detections dashboard, triage queue, briefing |
| `Hosts:read` | Hosts dashboard, investigate |
| `Vulnerabilities:read` | Vulnerabilities dashboard, patch plans |
| `Indicators (Falcon Intelligence):read`, `Actors (Falcon Intelligence):read` | Intel pivots and adversary exposure |
| `Real time response:read` / `Real time response (admin):read` | Live host introspection |
| `NGSIEM:read` | Natural-language → CQL hunting |
| `Hosts:write`, `Host Group:write`, `Workflow:write` | Only for the approval-gated write actions (containment, host-group membership, workflow execute) |

Save the **client ID** and **client secret**, and note your **regional API base URL** (US-1: `https://api.crowdstrike.com`, US-2: `https://api.us-2.crowdstrike.com`, EU-1: `https://api.eu-1.crowdstrike.com`, US-GOV: `https://api.laggar.gcw.crowdstrike.com`). The base URL must match the tenant's region.

---

## 2. Clone and install

```bash
git clone git@github.com:GTStagg/project-eyas.git
cd project-eyas
```

```bash
npm ci
python3 -m venv falcon-extras/.venv
falcon-extras/.venv/bin/pip install -r falcon-extras/requirements.txt
```


---

## 3. Configure

Create `.env` with a session secret — it seals the login cookie and is the root key for the encrypted credential store:

```bash
echo "AUTH_SESSION_SECRET=$(openssl rand -hex 32)" >> .env
chmod 600 .env
```

That's the only required value. **Falcon and Anthropic credentials are not put in `.env`** — you enter them in the browser in step 4, and they're stored AES-256-GCM-encrypted in `data/eyas.db`. Optional knobs (scheduler cadence, outbound webhook, daily budget banner) are documented in [`.env.example`](./.env.example).

---

## 4. Run

```bash
npm run dev            # http://127.0.0.1:3000
```

Open [http://127.0.0.1:3000](http://127.0.0.1:3000). On first run you land on **/register**: set a password, then enter your Falcon client ID / secret / base URL and your Anthropic key (or gateway). More tenants can be added later on `/config`.

The first Falcon call builds `eyas-mcp` from the pinned commit (about 30 seconds, once); later calls reuse the cached build.

---

## 5. First-run smoke test

1. Open **/status** — the **Anthropic**, **CrowdStrike Falcon** and **Falcon operations add-on** rows should be green; *Live versions* shows the resolved MCP server version.
2. In chat, paste:
   > List the names of every tool you have available. One per line. Do not call any tool.

   The trace shows a `ready` event with a `tool_count` in the mid-200s (the MCP server's tools plus the sidecar's ~70, minus some the console hides), then the list.
3. Try a real query:
   > Show me the last 5 critical detections.

   The trace should show `falcon_search_detections` being invoked, then a markdown table.

---

## 6. The `falcon-extras` sidecar

Always on. It adds capabilities the MCP server doesn't cover — host containment, host-group membership, Fusion workflow execute, agentic patching, the agentic IR cleanup catalog, process-tree reconstruction, RAT-install scan, Recon corpus search, Identity Protection, Prevention Policy posture, and NGSIEM search with CQL linting — and wraps some writes with safer defaults. The venv from step 2 is all it needs in dev; the standalone bundle builds it on first launch from bundled wheels.

Write actions (containment, host-group changes, workflow execute, …) need the matching write scopes and always stop for your approval in the UI.

---

## 7. Build the standalone bundle (optional)

```bash
./make-dist.sh
```

Stop the dev server first — the build rewrites `.next/`. The zip lands in the project root; install it on the target Mac with [`docs/STANDALONE.md`](./docs/STANDALONE.md) (Part 3).

---

## 8. Docker

Compose builds two images from source: the app from this checkout, and `eyas-mcp` from GitHub at the commit pinned in `versions.json` (nothing is pulled from a container registry). Compose reads `.env` the traditional way: set `AUTH_SESSION_SECRET` and `FALCON_MCP_API_KEY` (each `openssl rand -hex 32`); the API key protects the MCP server's HTTP endpoint on the private Docker network, and the MCP container refuses to start without it. Then:

```sh
docker compose up -d --build
```

The app is published on `127.0.0.1:3000` only. Register from that address; see [`docs/DEPLOYMENT.md`](./docs/DEPLOYMENT.md) for putting a reverse proxy in front.

---

## 9. Troubleshooting

**The MCP server row on /status is red / "Connection closed"** — `uvx` couldn't build `eyas-mcp`. Check that the machine can reach `https://github.com/GTStagg/eyas-mcp` and that `uv` is on the PATH of the shell that ran `npm run dev`. Run `npm run upgrade-mcp` to rebuild from a clean cache.

**`403` / "scope pending" on a surface** — the API client lacks the scope that surface needs. `/config` lists what each scope unlocks; grant it in the Falcon console and reload.

**Every Falcon call `401`s even though the token mints** — the base URL doesn't match the tenant's cloud region.

**Anthropic 429 (rate limit) mid-demo** — the system prompt + tool definitions are large enough to trip a low-tier account's input-token limit. In order of disruption:
1. Wait 60s and retry — the prompt cache will hit and the next call is far cheaper.
2. Switch to a Haiku model on `/config` (Anthropic card → Model).
3. Add credits in the Anthropic console to raise your tier.

**The operations add-on row is red** — the sidecar venv is missing or broken; re-run the two `falcon-extras/.venv` lines from step 2.

**Chat returns `sessionId required`** — the UI sets this automatically; you only see it when calling the API directly with `curl`. Add `"sessionId":"smoketest"` to the JSON body.
