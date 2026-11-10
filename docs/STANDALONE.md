# Eyas — macOS onboarding

End-to-end walkthrough from a clean macOS install to a fully provisioned tenant. One linear read; follow top to bottom. No Docker, no reverse proxy, no separate sidecar container — the Next.js process spawns the `eyas-mcp` MCP server and the `falcon-extras` Python sidecar locally and binds to loopback.

> Looking for the Linux/Docker deployment? See [`DEPLOYMENT.md`](./DEPLOYMENT.md). Deep references for IR and Shadow-AI provisioning live in [`IR-SETUP.md`](./IR-SETUP.md) and [`SHADOW-AI-SETUP.md`](./SHADOW-AI-SETUP.md). Once the tool is running, the operator-facing tour is [`USERGUIDE.md`](./USERGUIDE.md).

**What you'll have when you're done:** a local console at `http://127.0.0.1:3000`, signed in with your own password, talking to your Falcon tenant via an approved API client, with the IR quarantine and Shadow-AI Banned posture standing up on the Falcon side so the agentic IR + Shadow-AI surfaces are usable on day one.

Allow **~20 minutes** on a fresh Mac (most of that is brew installs and waiting for Falcon prevention-policy propagation).

---

## Part 1 — Install prerequisites (clean Mac)

Skip any tool you already have. All commands run in **Terminal.app** (`Applications → Utilities → Terminal`, or `Cmd+Space` → "Terminal").

### 1.1 Homebrew

[Homebrew](https://brew.sh) is the macOS package manager — every other prereq installs through it. Skip if `brew --version` already prints a version.

```sh
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

The installer will prompt for your Mac password (installing into `/opt/homebrew` on Apple Silicon, `/usr/local` on Intel). When it finishes, it prints two `eval` commands under "Next steps:" — **run them**, or `brew` won't be on your PATH in future shells. They look like:

```sh
echo >> ~/.zprofile
echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
eval "$(/opt/homebrew/bin/brew shellenv)"
```

Verify: `brew --version` should print `Homebrew 4.x`.

### 1.2 Node.js (22 LTS or 24)

Runs the Next.js server (the console UI). The bundle ships native database
bindings precompiled for Node 22 LTS (ABI 127) and Node 24 (ABI 137);
`start.sh` picks the matching one automatically. Other Node majors will
print a clear error on launch listing the supported ABIs.

```sh
brew install node          # current stable (Node 24 at the time of writing)
# or
brew install node@22       # LTS — recommended if you don't have a preference
```

Verify: `node --version` should print `v22.x` or `v24.x`.

### 1.3 Python 3.12

Hosts the bundled `eyas-mcp` server and the `falcon-extras` FalconPy sidecar. macOS ships Python 3.9, which is too old (eyas-mcp requires ≥3.11). The standalone bundle's wheels are built for 3.12 by default, so install that minor version explicitly.

```sh
brew install python@3.12
```

Verify: `python3.12 --version` should print `Python 3.12.x`.

The same `python3.12` is reused by both `eyas-mcp` and the `falcon-extras` sidecar — no second install needed.

### 1.4 uv (online bundles only)

**Skip this step** if your bundle contains a `vendor/falcon-mcp-wheels/` directory — that's the offline path and Python 3.12 alone is enough. Only needed when the bundle was built without pre-downloaded wheels and the target Mac has unrestricted PyPI access.

```sh
brew install uv
```

Verify: `uvx --version` should print `uv 0.x`.

---

## Part 2 — Gather credentials

Have these in front of you before launching — the `/register` wizard asks for them.

### 2.1 Anthropic

An **API key** from [console.anthropic.com](https://console.anthropic.com) → *Settings → API keys*. Starts with `sk-ant-…`.

Or, if your org runs a corporate Anthropic gateway, the gateway's **bearer token + base URL** instead.

### 2.2 Falcon API client

In the Falcon console: *Support → API Clients and Keys* → *Create API client*. You'll get a Client ID + Client Secret. Grant these scopes (the wizard lists them too, with a copy-paste checklist):

- **Alerts** read · **Incidents** read · **Hosts** read+write · **Vulnerabilities** read
- **Indicators (Falcon Intelligence)** read · **Actors (Falcon Intelligence)** read
- **Real Time Response** read+write · **Custom IOC** read+write
- **Sensor Usage** read · **NGSIEM** read
- **Host Group** read+write — enables IR + Shadow-AI host-group provisioning
- **Prevention Policies** read+write — enables IR + Shadow-AI policy provisioning
- **Custom IOA Rules** read+write — enables the Shadow-AI rule group
- **IOA Exclusions** read+write — enables the IR-readiness exclusion
- **Workflow** read+write — enables agentic Workflows execute

Surfaces light up automatically as scopes are granted; pages whose required scope isn't on your client appear staged with a *scope pending* note. You can grant the minimum (read-only) up front and add write scopes later — the Getting Started checklist will re-detect.

### 2.3 Falcon region URL

`https://api.crowdstrike.com` (US-1, default), `https://api.us-2.crowdstrike.com`, `https://api.eu-1.crowdstrike.com`, or `https://api.laggar.gcw.crowdstrike.com` (US-GOV). Visible in the Falcon console URL bar when you're logged in.

---

## Part 3 — Install and launch

The bundle ships an installer that puts a small `eyas` command on your PATH, so you can start and stop the console from anywhere — you don't have to keep the download folder around or remember where it lives.

### 3.1 Install

No prebuilt bundles are published — build one from source with `./make-dist.sh` (see [Building the bundle](#building-the-bundle)), then continue here with the zip it writes to the project root.

1. Unzip the bundle:
   ```sh
   unzip project-eyas-v<version>.zip
   cd project-eyas-v<version>
   ```

2. Run the installer:
   ```sh
   bash install.sh
   ```

   It copies the app into `~/.local/share/project-eyas`, adds an `eyas` command to `~/.local/bin`, and puts that directory on your PATH. Running a newer bundle's `install.sh` later upgrades the app in place and never touches your saved password, credentials, or data.

   If it prints a note about opening a new Terminal window, do that (or run `source ~/.zshrc`) so the `eyas` command is recognized.

### 3.2 Launch

```sh
eyas
```

First launch takes a minute — it sets up the bundled Falcon components, then starts the console on `http://127.0.0.1:3000` and opens your browser. Available commands:

| Command | What it does |
|---|---|
| `eyas` | Start in the background and open the browser (default) |
| `eyas stop` | Stop the console |
| `eyas status` | Is it running? |
| `eyas logs` | Follow the server log |

The browser opens to `/register` on first run. Continue to Part 4.

### 3.3 Run without installing (optional)

To try the console without installing the `eyas` command, run it in the foreground from the unzipped folder:

```sh
./start.sh
```

It starts the same way but stays attached to the terminal (`Ctrl-C` to stop).

**If it can't find Python 3.10+:** your shell hasn't picked up brew's path. Force the right interpreter:
```sh
PYTHON3=$(which python3.12) ./start.sh
```

### 3.4 Staying up to date

To upgrade, pull the latest source and rebuild the bundle (`./make-dist.sh`), then stop the console, run the new bundle's installer, and start again:

```sh
eyas stop
cd project-eyas-v<new-version>
bash install.sh
eyas
```

Your password, credentials, and data are kept.

---

## Part 4 — The `/register` wizard

Two steps. Everything you enter persists in `data/eyas.db` (mode 0600) so a new tab on next launch goes straight to `/login`.

### Step 1 — Console password

≥12 characters. This is the only credential that can sign into the console afterward — the hash lives in `data/eyas.db`. There is no password reset; if you forget it, stop the server, delete `data/eyas.db`, and re-register.

### Step 2 — Integration credentials

| Field | Source |
|---|---|
| **Anthropic API key** or **Auth token + Base URL** | Part 2.1 |
| **Falcon Client ID** | Part 2.2 |
| **Falcon Client Secret** | Part 2.2 |
| **Falcon Base URL** | Part 2.3 |
| **Member CID** (optional) | MSSP / Flight Control child CID. Leave blank for single-tenant. |
| **IR quarantine group ID** (optional) | Leave blank; the Getting Started checklist provisions this for you in Part 6. |
| **Shadow-AI Banned group ID** (optional) | Leave blank; provisioned in Part 7. |

The **Test connection** button probes both Anthropic and Falcon with an OAuth2 round-trip before save. Don't skip it — a typo here means the chat fails on every turn until you re-edit.

On save, the browser routes to the home page. You're signed in.

**Adding more Falcon tenants later:** the TopBar environment chip lists every saved environment and switches in one click. Add via *+ Add environment*; each has its own Client ID/Secret/Base URL/Member CID/IR group/Shadow-AI group. Switching is refused while an agent run is in flight so credentials never rotate mid-tool-call.

**Editing the active connection:** `/status` → *Falcon connection* → *Edit*. Same probe-before-write gate.

---

## Part 5 — The Getting Started checklist

Browse to the home page. The Getting Started checklist runs five live probes and renders one row per step. Each row turns green as its prerequisite is satisfied.

| # | Row | What it checks | How to satisfy |
|---|---|---|---|
| 1 | **Anthropic API** | Saved Anthropic credential authenticates against `/v1/messages`. | Completed in Part 4. |
| 2 | **CrowdStrike Falcon API** | Saved Falcon client authenticates against the OAuth2 token endpoint. | Completed in Part 4. |
| 3 | **Falcon API scope coverage** | Which surfaces are unlocked by your currently-granted scopes. | Grant more scopes in the Falcon console (Part 2.2), then refresh. Open `/status` to see per-module detail. |
| 4 | **IR quarantine setup** | The IR quarantine host group + per-platform prevention policies + IR-readiness IOA exclusion exist on your tenant. | Part 6 below. |
| 5 | **Shadow-AI prevention** | The Shadow-AI Banned host group + per-platform prevention policies + per-platform Custom IOA rule groups exist on your tenant. | Part 7 below. |

You can start using the read-only surfaces (Detections, Hosts, Vulnerabilities, Queue, NGSIEM playground, chat) immediately after Part 4. Parts 6 and 7 unlock the write-side agentic workflows (agentic IR, Shadow-AI Ban+Clean).

---

## Part 6 — Provision IR quarantine

The agentic IR workflow assumes three Falcon-side artifacts:

1. A static **host group** (`Project Eyas - IR Quarantine`) that hosts get added to during Phase 1 and removed from during Phase 4.
2. **Three platform-specific prevention policies** (Windows / macOS / Linux), all attached to the group, all sliders pushed to `AGGRESSIVE`, all behavioral toggles enabled.
3. An **IOA exclusion** (`Project Eyas IR — RTR runscript preamble`) scoped to the group, so the aggressive prevention policy doesn't block the RTR runscript preamble during cleanup.

**To provision:** open `/config` → scroll to the **IR quarantine setup** card. The card probes your tenant and surfaces one of these CTAs:

- **Create everything** — no existing artifacts. The card composes a primer that hands off to chat; you approve `extras_create_quarantine_host_group` then `extras_provision_quarantine_policy` (which also installs the IOA exclusion). Two clicks total.
- **Adopt + standardize** — you already have a quarantine group (id pasted into the active environment). The card renames the attached policies to canonical naming, pushes the AGGRESSIVE settings, and installs the exclusion.
- **Create dedicated** — your group's policy is shared with other groups. The card creates new policies bound only to your IR group, leaving the shared policy untouched.

Each `extras_*` write tool fires an explicit approval gate in the chat UI. Nothing happens without you clicking **Approve**.

**Propagation:** the exclusion is pre-warmed at provisioning so it propagates to every sensor in the group well before the first IR engagement (60–90 seconds typically; sometimes minutes). On a brand-new tenant that's never seen a PShellMimikatz detection, the exclusion's pattern_id can't be resolved yet — provisioning logs `pattern_id_unresolved: true` and the first IR engagement falls back to a JIT install path. After that, re-run provisioning and the eager path takes over.

**For the deep reference** (migration cases, what each artifact does, decommissioning, manual verification in Falcon Console): [`IR-SETUP.md`](./IR-SETUP.md).

Once row 4 of the Getting Started checklist turns green, the `/queue` page's per-host **IR** chip works end-to-end.

---

## Part 7 — Provision Shadow-AI Banned

The Shadow-AI Banned enforcement assumes four artifacts:

1. A static **host group** (`Project Eyas - Shadow-AI Banned`), empty by default. Operators add hosts on a per-user basis.
2. **Three platform-specific prevention policies** (Windows / macOS / Linux), all set to AGGRESSIVE.
3. **Three platform-specific Custom IOA rule groups** (per-platform corpora — Cursor, Ollama, LM Studio, Claude Desktop, ComfyUI, MCP-host runtimes, Aider, Open Interpreter, DeepSeek model loads, plus installer-shape rules on Windows).
4. **Operator-managed membership** in the Banned host group, driven by the `/shadow-ai` page's Ban+Clean action.

**To provision:** `/config` → **Shadow-AI Banned setup** card. Same shape as the IR card — *Create everything* / *Adopt + standardize* / *Create dedicated* / *rules_incomplete* CTAs depending on tenant state. Each platform's rule-group adoption is a separate approval.

**Default-allow, opt-in to enforcement.** Standard prevention policies do NOT have the Shadow-AI rule group attached. Users CAN install AI tools by default. The operator only intervenes when a specific user needs to be blocked — they add the host to the Banned group via `/shadow-ai`, the banned policy wins by precedence, and the rule group fires for that host only.

**Sanctioning** is per-tool and lives on the active environment record. Flip the per-tool Sanction toggle in `/shadow-ai` for products your org has licensed (e.g., Microsoft Copilot, GitHub Copilot) and their signals drop from the verdict bag automatically. Microsoft Copilot family in particular is never uninstalled — sanction or out-of-band (GPO, Intune, M365 admin) is the correct lane.

**For the deep reference** (per-platform regex constraints, MSIX vs Squirrel handling, decommissioning): [`SHADOW-AI-SETUP.md`](./SHADOW-AI-SETUP.md).

Once row 5 turns green, the `/shadow-ai` page's per-host **Ban+Clean** chip works end-to-end.

---

## Part 8 — First useful prompts

Read [`USERGUIDE.md`](./USERGUIDE.md) for the persona tour. As a starting point:

- **SOC**: open `/queue`. Pick the top row, click **Investigate**. The agent will reconstruct the chain across detections, processes, hosts, and intel without you asking it to.
- **Falcon admin**: open `/prevention`. The decision document tells you which prevention sliders are below recommended posture and what changing each one would mean for current detection volume.
- **IR**: open `/hosts`, search for an affected host, click the per-host **IR** chip. The agentic IR workflow walks through quarantine → cleanup → verification → release with approval gates on every write.

The chat surface itself is intentionally bare — `$ agent --ready` prompt and three starter lines. Type anything; the agent will pick its tools and explain what it's doing as it goes. Every tool call is gated, traced, and auditable.

---

## Updating

To install a newer version:

1. Stop the running app (`Ctrl-C`).
2. Unzip the new bundle to a fresh directory.
3. Copy `.env` from the old install: `cp /path/to/old/.env ./.env`
4. Copy the entire `data/` folder from the old install: `cp -R /path/to/old/data ./`
5. Run `./start.sh`.

Deleting the old directory is safe once `.env` and `data/` are copied across.

**What's in `data/`** (so you know what survives a relocation):

| File | Purpose | What happens if you don't copy it |
|---|---|---|
| `data/eyas.db` | Single SQLite database holding the console sign-in password hash, Anthropic + every saved Falcon environment, the active-env pointer, sanctioned-tool list, append-only settings audit, per-IR-engagement audit records, and per-turn token-spend history. Mode 0600. Credentials are AES-256-GCM column-encrypted. | First launch routes you through `/register`. Historical IR records and cost telemetry are gone but new ones still log. |
| `data/perf-log.jsonl` | Optional per-request perf log (only present when `PERF_LOG=true`). | Historical timing data lost; new entries still log. |

Copying the whole `data/` folder covers everything in one move.

---

## Environment variables

Most values land in `data/eyas.db` via the wizard. `.env` is only consulted for bootstrap / overrides. Highlights:

| Variable | Required | Purpose |
|---|---|---|
| `ANTHROPIC_API_KEY` | one of these | Direct Anthropic API key (sent as `x-api-key`) |
| `ANTHROPIC_AUTH_TOKEN` | one of these | Bearer token for a corporate AI gateway. Mutually exclusive with `ANTHROPIC_API_KEY`. |
| `ANTHROPIC_BASE_URL` | with `ANTHROPIC_AUTH_TOKEN` | Gateway URL. Optional with a direct API key. |
| `ANTHROPIC_MODEL` | no | Override default Claude model (`claude-sonnet-5-5`; `claude-opus-5-5` for the highest quality). |
| `FALCON_CLIENT_ID` | first-run bootstrap | Wizard writes to `data/eyas.db` after first run. |
| `FALCON_CLIENT_SECRET` | first-run bootstrap | Same. |
| `FALCON_BASE_URL` | first-run bootstrap | Same. |
| `FALCON_MEMBER_CID` | no | MSSP / Flight Control child CID. Bootstrap-only; per-env after first run. |
| `FALCON_MCP_MODULES` | no | Comma-separated subset of the MCP server's modules. Default loads every module; capability gating follows your actual API scopes, so there's normally no reason to set this. |
| `FALCON_MCP_COMMAND` | no | Override the stdio command (default `uvx`). |
| `FALCON_MCP_ARGS` | no | Override the stdio args (default `eyas-mcp --transport stdio`). |
| `AUTH_SESSION_SECRET` | auto | Encrypts the session cookie. `start.sh` auto-generates one and writes it to `.env` on first run. |
| `OUTBOUND_WEBHOOK_URL` | no | If set, agentic outputs render a "Send to webhook" button that POSTs the report as JSON. |
| `CHAT_MAX_ITERATIONS` | no | Cap on agent-loop iterations per chat turn. Default `25`. |
| `FALCON_DATA_DIR` | no | Override the runtime data directory. Default `./data`. |
| `PORT` | no | Port to bind. Default `3000`. |
| `HOSTNAME` | no | Interface to bind. Default `127.0.0.1` (loopback only). |
| `PYTHON3` | no | Force a specific Python interpreter when `start.sh` can't find one. |

**Do NOT set** `FALCON_MCP_URL` in the standalone deployment — that switches the transport to HTTP and is Docker-only.

---

## Troubleshooting

**`ERROR: Node.js v20 or newer is required`**
Upgrade Node: `brew upgrade node`. If `brew` isn't installed, get the LTS installer from [nodejs.org](https://nodejs.org).

**`ERROR: No better-sqlite3 prebuild for Node ABI <N>`**
You're running a Node major the bundle wasn't built for. The error lists the ABIs the bundle ships. Install one of those Node majors (e.g. `brew install node@22` for ABI 127, `brew install node` for the current major at the time the bundle was built), then re-run `start.sh`. The bundle ships precompiled SQLite bindings for offline use — it can't compile new ones on your machine.

**"`better_sqlite3.node` Not Opened — Apple could not verify free of malware"**
First-launch macOS Gatekeeper warning on the unsigned native database binding. `start.sh` strips the quarantine attribute automatically on launch, so this should not appear if you run `./start.sh` rather than double-clicking the `.node` file. If it does appear, run `xattr -dr com.apple.quarantine /path/to/project-eyas-vX.Y.Z` once against the unzipped folder, then re-run `./start.sh`.

**`ERROR: uv (uvx) is not installed`** (online bundles only)
`brew install uv` — or `curl -LsSf https://astral.sh/uv/install.sh | sh`. Restart your terminal so the new PATH takes effect.

**`uvx could not run the MCP server`**
You're on the online path (a bundle built without wheels, or a source checkout) and `uvx` couldn't build `eyas-mcp` from the commit pinned in `versions.json`. Run `npm run upgrade-mcp` (source checkout) to see the underlying error.
- `invalid peer certificate: UnknownIssuer` → TLS interception on your network. Add `UV_SYSTEM_CERTS=true` to `.env` (uses the macOS keychain instead of uv's bundled roots).
- `No solution found ...` for a dependency → a package mirror that lacks it. Set `UV_INDEX_URL` in `.env` to an index that has it (e.g. `https://pypi.org/simple`).
- `client error (Connect)` and you're behind browser isolation / strict egress → switch to the offline bundle (rebuild with `uv` on a non-isolated host so wheels get pre-downloaded; see *Building the bundle* below).

**Offline install fails: `Could not find a version that satisfies the requirement`**
The bundled wheels don't match your `python3` version. The bundle is built for one Python minor version (3.12 by default). Either install the matching Python (`brew install python@3.12`, then `PYTHON3=$(which python3.12) ./start.sh`, and you may need to remove `vendor/falcon-mcp-venv/` so start.sh recreates it), or rebuild the bundle for your version (`WHEELS_PYTHON_VERSION=3.13 ./make-dist.sh`).

**Offline install fails: `Cannot install ... has invalid wheel filename` or arch mismatch**
Wheels were built for the wrong CPU architecture. Apple Silicon Macs need `macosx_11_0_arm64` (default); Intel Macs need `WHEELS_PIP_PLATFORM=macosx_10_9_x86_64` at build time.

**The browser opens but the chat says "MCP connection failed"**
Check `FALCON_CLIENT_ID` / `FALCON_CLIENT_SECRET` / `FALCON_BASE_URL` are correct for your region and that the API client has the scopes for the modules you've enabled. The terminal running `start.sh` will print the underlying MCP server stderr.

**Anthropic calls are blocked by the corporate gateway**
In the wizard, switch to *Gateway* — supply `ANTHROPIC_AUTH_TOKEN` (the gateway's bearer token) plus the gateway's base URL. The Anthropic SDK then sends `Authorization: Bearer <token>` against that URL.

**Chat says `Model "claude-sonnet-5-5" not found`**
You're on a gateway that only allowlists certain model ids. List what the gateway exposes and pin to one of those:
```sh
curl -s -H "Authorization: Bearer $ANTHROPIC_AUTH_TOKEN" \
     "$ANTHROPIC_BASE_URL/v1/models" | jq -r '.data[].id'
```
Set `ANTHROPIC_MODEL=<one-of-those-ids>` in `.env` and restart. If the gateway 404s `/v1/models` too, ask your gateway admin which Claude ids are exposed.

**`/status` shows Anthropic red on a gateway even though chat works**
Many gateways forward only `/v1/messages` and 404 the `/v1/models` endpoint that the health probe uses. The build detects this and downgrades to a green status with an explanatory note when `ANTHROPIC_AUTH_TOKEN` is set.

**`/status` shows an amber "setting up" state right after install or upgrade**
Expected on the first launch after a fresh install or an upgrade. The console builds its bundled offline components before it's fully ready; while that runs (usually under a minute), the CrowdStrike Falcon and Falcon operations add-on rows show an amber **setup** badge rather than green. Wait a moment and reload — they turn green once setup finishes. If a row is still amber after a couple of minutes, check the terminal/logs (`eyas logs`) for an install error.

**IR row stays red even after running the setup card**
Open `/config`, click *Re-detect* on the IR quarantine setup card. If it still reports missing artifacts, check the chat transcript from the provisioning run — every `extras_provision_quarantine_policy` call returns a structured result that names which step failed. Common cause: the API client is missing `Prevention Policies:write` or `IOA Exclusions:write`. Grant the scope, then re-fire.

**Port 3000 is already in use**
Set `PORT=3100` (or any free port) in `.env` and re-run `start.sh`.

**Browser opens to the wrong URL or doesn't open at all**
The browser-open step is best-effort. Navigate to `http://127.0.0.1:<PORT>` manually.

---

## Security notes

- The server binds to **`127.0.0.1` only** by default — not reachable from other hosts on your network. Don't expose it; this build is single-host, single-user.
- All credentials live in `data/eyas.db` on the local filesystem, mode 0600, atomic tmp+rename writes. Treat that file like an SSH key. If `data/` is in a synced folder (iCloud Drive, Dropbox), it ships your plaintext credentials with it — don't put it there.
- The cost log in `data/eyas.db` records token usage per turn — useful for budget tracking, doesn't contain prompt or response content.
- Write-capable tools (IOC creation, RTR commands, host containment, prevention-policy mutation, host-group mutation) always pause for explicit user approval in the UI before executing. There's no "auto-approve" mode.
- `lib/llm/anthropic.ts` and `lib/mcp/*.ts` are server-only modules. The browser never sees an API key.

---

## Building the bundle

Run from the project root on a host with PyPI access (or set `PIP_INDEX_URL` to a mirror):

```sh
./make-dist.sh
```

By default the bundle accepts either a direct Anthropic API key or a gateway on first run. To build a bundle locked to one Anthropic gateway (the API-key option is hidden and the URL can't be changed without rebuilding), set the gateway URL at build time:

```sh
ANTHROPIC_GATEWAY_BASE_URL=https://gateway.example.com ./make-dist.sh
```

The script builds the `eyas-mcp` wheel from the commit pinned in `versions.json` and downloads every runtime dependency into `vendor/falcon-mcp-wheels/` (the sidecar's hash-locked dependencies go to `vendor/falcon-extras-wheels/`), so the bundle installs **offline** on the target Mac. If any download fails, the build stops rather than ship a bundle that needs network access at first launch.

Override the Python version / platform the wheels are built for:

```sh
WHEELS_PYTHON_VERSION=3.13 ./make-dist.sh                              # for python@3.13 targets
WHEELS_PIP_PLATFORM=macosx_10_9_x86_64 ./make-dist.sh                  # for Intel Macs
WHEELS_PYTHON_VERSION=3.12 WHEELS_PIP_PLATFORM=macosx_11_0_arm64 …     # explicit defaults
```

Match the target Mac's `python3 --version` and architecture. To support both architectures, build twice and ship the right zip per host.

The resulting zip is written to the project root: `project-eyas-v<version>.zip`. Move it to the macOS host, unzip, follow Part 3.

After every build, validate the bundle:

```sh
/validate-bundle
```

(Claude Code skill — structural checks + optional smoke-boot.)

---

## What's in the bundle

```
project-eyas-v<version>/
├── server.js                ← Next.js standalone server entry point
├── .next/                   ← compiled app + static assets
├── public/                  ← static assets
├── node_modules/            ← minimal runtime deps
├── falcon-extras/           ← FalconPy Python sidecar (always-on)
├── vendor/falcon-mcp-wheels/    ← pre-downloaded eyas-mcp wheels + dependencies
├── vendor/falcon-extras-wheels/ ← (offline bundles only) pre-downloaded falcon-extras wheels
├── vendor/falcon-mcp-venv/      ← created on first launch by start.sh (offline path)
├── start.sh                 ← launcher (prereq checks + .env load + open browser)
├── .env.example             ← config template
└── BUILD-INFO               ← version + commit metadata
```

The bundle does **not** contain TypeScript source, Playwright fixtures, the Dockerfile / docker-compose.yml, or documentation other than this file.
