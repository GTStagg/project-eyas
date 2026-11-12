# Security

Eyas is a self-hosted, single-user agentic console. This file documents its
current security posture and how to report a vulnerability.

## Threat model

- **Operator**: one authenticated user per deployment instance. scrypt
  password hash stored in the single-row `auth` table of `data/eyas.db`;
  iron-session cookie, 7-day rolling. The cookie's `Secure` attribute is
  derived from the request scheme (`x-forwarded-proto`), not `NODE_ENV`: a
  TLS-terminating reverse proxy sets the header so real HTTPS deploys get
  `Secure`, while the direct-HTTP localhost standalone bundle (which runs
  `NODE_ENV=production`) relaxes it so the browser doesn't silently drop the
  cookie and log the operator out.
- **Network exposure**: the Next.js process listens on `127.0.0.1:3000` by
  default; reverse-proxy fronting is the deployment-time concern
  (`docs/DEPLOYMENT.md`).
- **Upstream APIs**: Anthropic and Falcon are reached server-side only. No
  `NEXT_PUBLIC_*` env vars; no client-side calls.
- **Secrets at rest**: Falcon + Anthropic credentials are AES-256-GCM
  column-encrypted in `data/eyas.db` (mode 0600). The encryption key is
  derived via HKDF-SHA256 from `AUTH_SESSION_SECRET`, which lives in
  `.env` (also mode 0600) — outside the encrypted store, so an exfiltrated
  DB file on its own is unreadable. Rotating `AUTH_SESSION_SECRET`
  intentionally invalidates every encrypted credential.
- **Build-time deployment lock** (standalone bundles): `lib/config/build-flags.ts`
  bakes `gatewayOnly` + `forcedGatewayUrl` at compile time. The policy is
  enforced server-side at the read seam (`getAnthropicClient` +
  `validateAnthropicAgainstPolicy` in `lib/config/deployment-policy.ts`): on a
  gateway-locked build, any stored API key is dropped and the baked gateway URL
  is forced. A leaked bundle copy — even one with a hand-edited DB row — cannot
  be repointed at a personal Anthropic account.

## Where data goes

Eyas runs on your host, but an agentic console necessarily sends some Falcon
data to a language model. These are the destinations:

| Destination | What is sent | When |
|---|---|---|
| CrowdStrike Falcon API (your region's `api.*.crowdstrike.com`) | API calls with your Falcon API client credentials | Every dashboard and tool call. The MCP server runs on the Eyas host (as a child process, or as a container on a private Docker network) and calls the Falcon API directly. Eyas's own tools make their Falcon calls through it. |
| Anthropic API, or the gateway you configure | Your prompts, the conversation so far, and **the results of every tool the agent calls**, including Falcon detections, host details, vulnerabilities and similar records, plus knowledge-base passages retrieved for the turn | Chat, agentic panels, triage, reports and scheduled reports. Deterministic dashboards that don't involve the agent send nothing to the model. |
| CrowdStrike AIDR (optional, per environment) | The text of each chat prompt and each assistant reply | Only when AIDR is configured for the active environment |
| Webhook URLs you configure (optional) | Generated reports and briefings | When you send a report, or when a scheduled job you've enabled delivers one |
| GitHub API (`api.github.com`) | A request comparing Eyas's pinned eyas-mcp commit with eyas-mcp's latest (with `GITHUB_TOKEN` if you set one) | Only when the `release-watcher` scheduled job is enabled |

Running the MCP client inside Eyas, instead of through Anthropic's hosted MCP
connector, keeps your Falcon credentials on your host. It also means only the
tool results the agent actually requests reach the model. It does **not** keep
that Falcon data off the model provider. Configuring a corporate gateway
changes which endpoint receives model traffic. Retention and residency then
depend on that gateway and its upstream provider, not on Eyas.

## Per-tool approval gating

Every write-shape MCP tool (host containment, RTR cleanup, host-group
add/remove, IOC writes, etc.) pauses the agent loop and renders an
operator-facing approval card before executing. The registry of gated tools
lives at `lib/mcp/write-tools.ts::REQUIRES_APPROVAL`; callers cannot disable
the gate per-route. `/audit-write-tools` greps every `runAgentLoop` callsite
for accidental `requiresApproval: () => false` overrides.

Approval resolutions are bound to the originating chat session: a tab whose
`sessionId` doesn't match the pending approval's session is rejected with
`session_mismatch`. See `lib/chat/approvals.ts`. Concurrent turns on the same
session are refused with a 409 (per-session chat lock), closing a
last-writer-wins clobbering gap on double-submit or two-tab resume.

Two fail-closed backstops cover tools missing from the registry:

- **Native tools** that advertise `readOnlyHint: false` are gated, and the
  drift is logged.
- **Eyas's own tools** (`extras_*`, served in-process from `lib/eyas-tools/`)
  carry no annotations. Each one must be listed either in `REQUIRES_APPROVAL`
  or in `EXTRAS_READ_ONLY`, the reviewed read-only list. An Eyas tool in
  neither list is gated as a possible write.
  `npm run test:tool-classification` fails CI if any registered Eyas tool
  is unclassified.

Sub-agents have no approval path. They never see gated tools, native writes
flagged by annotation, or unclassified Eyas tools.

## Request and process isolation

- **Cross-site requests:** state-changing `/api` requests (POST, PUT, PATCH
  and DELETE) are rejected unless the browser marks them same-origin
  (`Sec-Fetch-Site`), or, for clients without that header, the `Origin`
  matches the host. `/api/scheduled/*` is exempt; it uses `SCHEDULER_TOKEN`.
  Next.js server actions (login, registration) carry their own Origin check.
- **First-run registration** is only served to localhost host names, plus
  any listed in `EYAS_ALLOWED_HOSTS`. The account row is claimed before
  credentials are saved, so a losing concurrent submission can't overwrite
  them.
- **Login throttling:** after five failures, each attempt waits 30 s,
  doubling to a 15-minute cap. See `docs/DEPLOYMENT.md` for
  `EYAS_TRUST_PROXY`.
- **Child processes:** eyas-mcp receives only the
  active environment's Falcon credentials and settings. It never receives
  `AUTH_SESSION_SECRET`, Anthropic or AIDR credentials, `SCHEDULER_TOKEN`,
  `GITHUB_TOKEN` or the webhook URL (`lib/config/spawn-env.ts`).
- **Anthropic base URL:** must be https (http only for localhost), carry no
  credentials, and not target link-local or cloud-metadata addresses. The
  first-run connection test reports only an HTTP status, never the upstream
  response body.
- **Data files:** `data/` is 0700. `eyas.db`, its `-wal` and `-shm` files,
  and pre-migration backups are 0600.

## Configuration integrity

Credential and environment changes flow through `mutateSettings`
(`lib/config/store.ts`), which commits the settings write **and** the
append-only `settings_audit` row as a single transaction — the in-memory cache
only advances after the combined commit, so a settings change can never persist
without its tamper-evidence audit row (or leave a stale cache behind). The
`settings_audit` table records field shape only, never values. Switching the
active Falcon environment is refused with a 409 while a chat turn is in flight,
so credentials can't be swapped out from under a running agent loop.

## IR engagement audit integrity

Each agentic incident-response engagement is recorded in two SQLite tables:
`ir_runs` (the kickoff facts the deterministic release backstops read — the
captured open-detection scope, whether the host was already contained, its
role) and `ir_run_turns` (the per-turn record of what the agent did and what
the operator approved). SQLite triggers enforce that `ir_run_turns` is
append-only — any `UPDATE` or `DELETE` fails loudly — and that the `ir_runs`
kickoff facts are immutable after insert (only the activity timestamp may
change).

This is tamper-**resistance**, not cryptographic tamper-**evidence**. The
triggers add friction: a direct edit or delete fails with a loud error instead
of silently succeeding, and a future retention/prune job must drop them
explicitly before it can touch either table. But there is no hash chain and no
WORM storage, so a privileged local actor with write access to `data/eyas.db`
can `DROP` the triggers and then rewrite history without leaving a trace. The
guarantee is "casual or accidental rewrites are blocked, and any tamper attempt
against the live tables fails loudly" — not "tampering by a privileged actor is
detectable after the fact."

## IR release safety backstops

The highest-blast-radius IR transitions — lifting network containment and
removing a host from its quarantine group — are not left to the agent's prose
judgment. Three deterministic checks run server-side at the tool-call seam, each
reading the engagement's *ground truth* from `ir_runs` / `ir_run_turns` (the
kickoff facts + the persisted per-turn record), never the model's narration or
the playbook's advisory flags:

- **Lift backstop (F1):** `falcon_lift_host_containment` targeting the run's host
  is refused unless THIS workflow is the one that applied containment (derived
  from the persisted approved contain turns whose result confirms the host in `succeeded_ids`). A
  containment that predates the engagement, or one applied by another actor, is
  the operator's to lift from the Falcon Console — the workflow will not undo it.
- **Group-remove backstop (F1-group):** `extras_host_group_remove_members` is
  refused unless THIS workflow is the one that added the host to that group.
- **Release gate (F2b):** both release writes are refused while a deterministic
  re-scan shows the engagement isn't actually clean — either real new detections
  fired during the window, or one of the exact Phase-0 original detections
  (re-checked by composite id) is still open. The gate **fails closed**: if the
  kickoff scope was never captured, the re-scan errors, or a version skew is
  detected, the release is blocked (the host stays held) rather than waved
  through.

These checks are **additive** — they can only ever *block* a write, never bypass
the per-tool approval gate (a blocked write is never even offered for approval).
A throw inside a check fails closed. The contain/lift approval cards also surface
the verified ground truth (was-contained-at-start, this-workflow-contained, host
role / Domain-Controller blast-radius) as a block distinct from the agent's
report, so the operator approves informed.

The backstops are keyed by **aid**, read from `ir_runs` (which never expires), so
they arm for any host with Eyas IR history regardless of which chat session — or
how long after kickoff — the release is attempted.

**Boundaries (deliberate, disclosed):**

- A host with **no Eyas IR history** — e.g. one contained manually in the Falcon
  Console and never run through the workflow — has no ground truth to key off, so
  the backstops do not arm and the transition degrades to approval-only (the
  operator still approves, but the card shows no verified facts). Backstopping a
  host the workflow never touched is out of scope.
- The release gate enforces at the **detection-status** layer (are the original
  detections closed / did new ones fire), not full artifact re-observation.
  Dormant persistence whose original detection was closed and which has not
  re-fired during the window can still be released. This ceiling is disclosed on
  the release approval card.

## Connection-test hardening (`/register`)

The first-run setup form's connection-probe action is the only credential-bearing
surface reachable before sign-in, and it is hardened against SSRF and credential
exfiltration:

- Once the app is registered, the probe requires an authenticated session
  (`isRegistered()` gate) — first-run setup is unaffected because no credentials
  exist yet to leak.
- The Falcon Base URL is allowlisted against `FALCON_BASE_URL_RE` before any
  credential leaves the process, so the server cannot be coerced into POSTing
  stored secrets to an attacker-chosen host or SSRF-ing an internal endpoint.
- The probe reuses `probeFalconCredentials`, which carries a 10s timeout (no
  unbounded fetch).
- On gateway-locked builds the Anthropic probe is forced to the baked gateway
  URL and never ships the token to a form- or DB-supplied host.

## Agent-supplied query input

Agent-supplied strings that are interpolated into Falcon FQL filter or GraphQL
query literals are validated, not escaped, before use. The MCP server's
identity tools check user names against a strict character set (and device IDs
as 32 hex characters) and build GraphQL strings with JSON encoding, so an
apostrophe or backslash can't break out of a literal and inject a filter. A
hard reject is safer and clearer than unreliable FQL escaping.

## CrowdStrike AIDR guardrail (optional, per-environment)

When AIDR is configured for the active environment, every chat prompt is scanned
**before** it reaches Anthropic and every assistant response is scanned **before**
it is saved (`lib/aidr/client.ts` — `scanInput` / `scanOutput`, wired as
pre-loop and post-loop gates *outside* the tool-use loop). The per-environment
AIDR token + base URL are stored encrypted at rest alongside the Falcon
credentials, and the base URL is allowlisted before persistence. Block verdicts
are recorded in the append-only `aidr_blocks` table (verdict + preview hash, not
the offending text). The gate fails open on transport error (an amber banner on
the turn, not a hard stop); a blocked **output** drops from the transcript so it
cannot leak into a later resume.

## Health endpoint split

- `/api/healthz` — public, no upstream calls. Suitable for orchestrator
  health probes and uptime monitors.
- `/api/health` — authenticated. Returns the full diagnostics (Anthropic
  probe, Falcon MCP probe, auth and AIDR probes). `?force=1` triggers a fresh
  fanout and is gated behind the same auth requirement.

## Dependency triage

Last reviewed **2026-11-08**. Re-run before each release:

```sh
npm ci
npm audit --omit=dev     # production dependencies
npm audit                # including dev tooling
```

Eyas itself has no Python dependencies. The Python packages in a bundle are
eyas-mcp's own, pinned with it in `versions.json`.

### Current state

- **npm, production:** `npm audit --omit=dev` reports **0 vulnerabilities**.
- **npm, dev-only:** `npm audit` reports **0 vulnerabilities**. The last
  dev-only advisory (esbuild GHSA-67mh-4wv8-2f99, through `drizzle-kit`) was
  cleared by removing `drizzle-kit`; migrations are hand-written SQL.

### Changes made in this review

- **`mammoth` 1.8.0 → 1.13.0** (GHSA-rmjr-87wv-gf87, directory traversal).
  It is reachable: uploaded `.docx` knowledge files are parsed with
  `mammoth.extractRawText` (`lib/knowledge/store.ts`).
- **`@modelcontextprotocol/sdk` 1.29.0 → 1.32.2** (GHSA-6prh-2h8m-c8cw). The
  HTTP client transport followed cross-origin redirects and re-sent custom
  headers, which is relevant on the Docker path, where Eyas sends `x-api-key`
  to the MCP server over HTTP.
- **`proxy-addr` 2.0.7 → 2.0.8** (GHSA-jqcg-44mw-7w3h, critical). It's
  transitive through `express`, which the MCP SDK uses only for its server
  side. Eyas uses the SDK as a client, so this wasn't reachable, but it's
  updated anyway.
- **In-range lockfile updates** (no API changes): `hono`, `@hono/node-server`,
  `@xmldom/xmldom`, `body-parser`, `fast-uri`, `ip-address`, `nanoid`, `qs`,
  `sharp`, `source-map-js`, `zod`.
- **`valibot` override 1.4.0 → 1.5.0**. It's a dependency of the vendored
  `@crowdstrike/aidr` package.
- **Next.js's internal `postcss`** is overridden from 8.4.31 to 8.5.31
  (`overrides.next.postcss` in `package.json`). That clears the PostCSS
  source-map and stringify advisories without a Next.js major upgrade. The
  production build was verified with the override.
- **`mcp` (Python sidecar, since removed) 1.27.0 → 1.30.0.** The sidecar spoke
  MCP over stdio only, so the HTTP and WebSocket transport advisories against
  1.27.0 weren't reachable.

New versions are chosen from releases at least two weeks old, to limit exposure
to compromised fresh publishes. The four vendored tarballs in
`vendor/npm-offline/` (`@anthropic-ai/sdk`, `@crowdstrike/aidr`, `geist`,
`iron-session`) are installed from `file:` specs; updating them means replacing
the tarball, not the lockfile entry.

## Residual risks

- `AUTH_SESSION_SECRET` is the only cookie-sealing + column-encryption-root
  key; rotation is supported (drop the env value, restart) but invalidates
  every encrypted credential in the DB — by design. No graceful re-key
  workflow today.
- `ANTHROPIC_LOG=debug` (set by the operator) writes tokens to stdout
  unredacted — do not enable in production logs.
- `data/eyas.db` mode 0600 protects against other Unix users on the same
  host. Folder backups (Time Machine, Dropbox sync, etc.) ship the
  ciphertext, but an attacker who also obtains `.env` from the same backup
  has the key — operators should keep `data/` and `.env` out of synced
  folders and treat the bundle directory as sensitive.
- Pending approval state is in-memory and process-local. A process restart
  drops in-flight approvals (the agent loop will time out at 5 minutes).
  Single-process by design; cross-replica approval is out of scope.
- IR engagement audit tables (`ir_runs`, `ir_run_turns`) are trigger-protected
  (append-only / immutable) for tamper *resistance*, not tamper *evidence*: a
  privileged local actor with DB write access can drop the triggers and rewrite
  the record untraceably. Cryptographic audit (hash-chained rows / external
  WORM) is out of scope.
## Reporting

Report vulnerabilities privately through GitHub's private vulnerability
reporting: the repository's **Security** tab → **Report a vulnerability**.
Please don't file security issues as public issues.
