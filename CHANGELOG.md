# Changelog

## 0.11.0 — Every Eyas tool runs in the console; the Python add-on is gone

### Changed
- **Removed the demo talk track and AI-specialist briefing** (`docs/DEMO.md`,
  `docs/AI-SPECIALIST.md`). Both were written for internal audiences; the
  user guide, deployment guides and whitepaper cover the product. Bundles no
  longer ship them.
- **MCP server pinned to eyas-mcp 11e9564** (still 0.21.0). A detection whose
  process Falcon blocked before it ran has no process-start record, so its
  process tree used to come back empty and the IR campaign scope left it
  ungrouped. eyas-mcp now builds that process from its block event and walks
  its parents, so blocked detections get a delivery vector and join their
  campaign. The detection drawer marks such a process "blocked".
- **MCP server pinned to eyas-mcp f9449d5** (still 0.21.0). eyas-mcp now
  lists its tools and resources in the same order in every process, so the
  prompt cache holds across restarts on its side too; Eyas keeps its own
  sorting as a backstop. `falcon_search_host_groups` caps `limit` at 500,
  which every Eyas caller already respects.
- **MCP server pinned to eyas-mcp 208acdd** (still 0.21.0). It adds host-group
  and policy lookups by id, safer host-group membership changes, relative
  policy precedence moves, a time limit and raw signing fields on process
  trees, batched alert lookups, and a warning for unknown CQL functions.
  `falcon_get_host_group_membership` now lists a group that no longer exists
  under `unresolved_group_ids` instead of failing; the IR playbook leaves
  those out of the Phase 4 restore.
  It also batches Custom IOA rule updates (up to 100 rules per call, each sent
  in full from the live rule), makes an IOA exclusion's `cl_regex` optional,
  adds an opt-in duplicate check on exclusion creates, and cleans comment and
  name characters Falcon would reject.
- **More of the add-on moved onto eyas-mcp.** Host-group and group-member
  listings, the contained-host list and identity detections now come straight
  from eyas-mcp's native searches; recording a detection verdict and running a
  Fusion workflow use eyas-mcp's native write tools (still approval-gated).
  Six add-on tools are gone; the add-on is down to 50.
- **The workflow playbooks run inside Eyas.** The IR, identity-IR, Shadow-AI
  and Data Protection playbooks are now served by Eyas itself instead of the
  add-on, with the same text and tool names. They read the quarantine and
  banned group ids from the active environment when called, and refuse a
  host id, group id or user name that isn't well-formed. The add-on is down
  to 46 tools.
- **The patch and cleanup script library runs inside Eyas.** Listing,
  resolving, dry-running and running patch and cleanup scripts, checking
  long-running patches, saved patch profiles and the vulnerability page's
  coverage check are served by Eyas instead of the add-on, under the same tool
  names, with every render checked against the former add-on's output. A
  patch profile saved earlier in a chat turn is now visible to a later step of
  the same turn. The add-on is down to 36 tools.
- **Host-group membership and IR quarantine setup run inside Eyas.** Adding
  and removing hosts from static groups uses eyas-mcp's membership action with
  explicit host ids (it refuses dynamic groups itself). Diagnosing, creating
  and adopting the IR quarantine group and the IR-readiness check now read
  the group from the active environment when called, so a group created or
  adopted earlier in a chat turn is seen straight away. The add-on is down to
  30 tools.
- **IR quarantine policy provisioning runs inside Eyas.** Adopting or creating
  the per-platform quarantine policies, raising their settings, ordering them
  first and installing the IR-readiness exclusion now use eyas-mcp's policy
  and exclusion tools. The precedence move asks eyas-mcp to put the policy
  first rather than resending a full order built from a partial list, so it
  can no longer reorder or drop unrelated policies. Detaching a policy from a
  group moved too. The add-on is down to 28 tools.
- **Tenant teardown runs inside Eyas.** The teardown and the single policy
  and rule-group deletes now use eyas-mcp's tools. The approval card says
  whether a teardown is a dry run or will delete objects. The add-on is down
  to 25 tools.
- **IR detection scope and closing run inside Eyas.** The Phase 0 scope and
  actionability check, the Phase 3 verification (and the release safeguard's
  re-check of the original detections), the remediation-ledger close, the
  close of untouched originals and the close-everything-on-a-host action now
  read and close detections through eyas-mcp, with the same results. A
  verification start time that isn't a plain timestamp is refused. The Phase 0
  and Phase 3 results now list their counts before the per-detection list, so
  a long list no longer cuts the counts off what the agent sees. The add-on
  is down to 19 tools.
- **Process tree, campaign scope and remote-access-tool scan moved into
  Eyas.** The detection drawer's process tree, the IR Phase 0 campaign scope
  and the remote-access-tool install scan now run in the console on
  eyas-mcp's process-tree walk and NGSIEM search, with Eyas's own
  delivery-vector classifier and clustering on top. A parent missing from the
  search window is now looked up over the previous 7 days (was ±60 minutes),
  the campaign scope's walks also re-centre on a long-running process and
  look up a missing parent, and nodes carry the sensor's raw signing fields
  and the image hash. Process start times are ISO timestamps. The add-on is
  down to 16 tools.
- **Shadow-AI host and fleet hunts moved into Eyas.** The per-host scan (AI
  apps, MCP servers and agent frameworks, AI egress, local model servers)
  and the fleet-wide egress search now run in the console on eyas-mcp's
  NGSIEM search, with the same catalog, cleanup plans, verdicts and
  sanctioned-tool handling. The host scan's three searches run at the same
  time instead of one after another, with a longer time limit each, so a
  busy host is less likely to come back partial. The add-on's own CQL checker
  is gone; eyas-mcp checks every query. The add-on is down to 14 tools.
- **Shadow-AI setup and prevention moved into Eyas.** The banned host group's
  check, create and adopt, the prevention-policy provisioning, the rule-group
  status, the enforcement-chain audit and the rule-bundle adoption now run in
  the console on eyas-mcp, with the same rule corpus, cases and results. The
  banned policy is now placed directly below the IR Quarantine policy without
  rewriting the rest of the platform's order. Adoption enables and
  re-dispositions rules in one call and leaves each rule's other fields as
  they are in Falcon. A group created or adopted earlier in a chat turn is
  seen straight away. The add-on is down to 7 tools (exclusions and Data
  Protection creates).
- **Exclusions and Data Protection creates moved into Eyas.** Listing and
  creating IOA / ML exclusions and creating Data Protection content patterns,
  classifications and policies now run in the console on eyas-mcp, with the
  same duplicate refusal, regex check and monitor-first defaults. The Tuning
  panel's exclusion check now comes from the eyas-mcp health probe. The add-on
  registers no tools any more and is removed in the next change.
- **The Falcon operations add-on is gone.** Every Eyas tool runs inside the
  console and reaches Falcon only through eyas-mcp, so the console no longer
  starts a second tool server. The standalone bundle and the Docker image no
  longer carry its Python code, its virtual environment or its packages; the
  bundle needs only Node and `uv` (for eyas-mcp). `/status` and the health
  report drop the add-on row, the home-page and getting-started scope checks
  read eyas-mcp's capability probes, and registration always continues to
  Getting started.
- Verdicts are now recorded as the `true_positive` / `false_positive` tag with
  `status='closed'` on the native detection update, the same tag the Falcon
  console writes.

### Fixed
- **Chat reuses its prompt cache between turns.** The tool list and the
  syntax-guide list came back from the MCP server in a different order each
  turn, so every chat message paid to cache the ~175K-token tool catalog
  again. They are now sorted, and the conversation so far is cached too, so a
  long investigation no longer re-sends every earlier tool result at the full
  price. On the dev instance a follow-up message dropped from about $0.70 to
  about $0.02.
- `/cost-summary` priced every call with older Claude Sonnet 4 rates and
  overstated spend by about half; it now reads the same price table as the
  in-app cost page.
- **Teardown removes the IR-readiness exclusion.** It looked for the text
  "IR-readiness" in the exclusion's comment, which the setup never writes, so
  the exclusion was left behind on every teardown. It is now matched by the
  RTR command-line marker the setup and the readiness check use.
- **Rendered patch and cleanup scripts keep every `?`.** The script
  renderer deleted every `?` along with the non-ASCII characters it meant to
  strip. That broke `rc=$?` exit-code checks in the Linux and macOS patch
  scripts, the Edge, Firefox and Zoom download URLs, generic-installer URLs
  with a query string, and several PowerShell regexes. Only non-ASCII
  characters are dropped now.
- **Windows patch scripts report a failed install.** The 13 scripts that use
  the shared installer helper captured its progress lines along with the
  exit code, so the log came out as one jumbled line at the end and a failed
  install (for example MSI 1603) still exited 0. They now print the progress
  lines in order and exit with the installer's code.
- The posture snapshot's contained-host count is no longer capped at 200.
- The approval card for a Fusion workflow run showed "(unspecified)" for the
  workflow; it now shows the definition id and the input.
- When the agent loaded the IR playbook itself (for example in the identity-IR
  cascade) it received only the first 12 KB of the ~70 KB text, because every
  tool result was capped. Playbook results now arrive in full. The IR button's
  server-side load was not affected.
- The cleanup script catalog (about 25 KB) reached the agent cut off at 12 KB,
  so it couldn't see every cleanup action before deciding one didn't exist.
  Both script catalogs now arrive in full.

### Security
- **Removed `drizzle-kit`**, a dev-only tool that pulled in an old esbuild
  (GHSA-67mh-4wv8-2f99). Migrations were already hand-written SQL run by Eyas's
  own runner, so nothing at runtime changes; `npm audit` is now clean. The
  `db:generate` / `db:studio` scripts and `drizzle.config.ts` are gone.

## 0.10.0 — Most of the add-on moves onto eyas-mcp; Claude 5.5 defaults

### Security
- **Login and registration hardening.** Failed logins are throttled (after five
  failures each attempt waits 30 s, doubling to 15 min). First-run
  registration is only served to localhost (extra host names via
  `EYAS_ALLOWED_HOSTS`) and can't be won by a racing second request.
  State-changing API requests from other sites are refused.
- **Child processes no longer receive the app's own secrets.** The MCP server
  and the Falcon operations add-on get only Falcon settings; the session /
  credential-encryption key, Anthropic credentials and other tokens stay in
  the web process.
- **Every add-on tool must be classified read-only or approval-gated**;
  an unclassified one is gated by default.
- **The dev and production servers bind to 127.0.0.1**, the Anthropic base URL
  must be https (http only for localhost), and bundles never ship the
  builder's `.env`.
- **Dependency updates:** React 19.3, lucide-react 0.577, drizzle-orm 0.45.4,
  better-sqlite3 12.11, FalconPy 1.6.6, Next.js 15.5.28, `mammoth` 1.13.0 (directory
  traversal), MCP SDK 1.32.2, Anthropic SDK 1.3.0 (Claude API version
  2026-10-21; now Apache-2.0 licensed), `proxy-addr` 2.0.8, Python `mcp` 1.30.0; the
  sidecar's Python dependencies are hash-locked. Third-party license notices
  ship with the bundle.

### Changed
- **The assistant can count search results again.** For Falcon searches, the
  total number of matching records now reaches the assistant ahead of the
  rows, so "how many host groups / hosts / …" questions get an exact answer
  even when the listing itself is too long to show in full.
- **Current Claude models.** The default model is now `claude-sonnet-5-5`, with
  `claude-opus-5-5` suggested for the highest quality. Every request now asks
  for a medium thinking effort (where the model supports it) and leaves room
  for thinking in its output limit, so answers aren't cut off. A request the
  model declines now ends with a plain notice instead of an error. On
  `claude-sonnet-5-5` and `claude-opus-5-5`, a request a safety check declines
  is now retried automatically on a fallback model in the same call, so
  routine security work is interrupted less often. Gateways that don't
  support this keep working without it. The cost
  page prices the current models correctly, and Opus 4.5 and later are no
  longer priced at the old Opus 4 rate.
- **Docs and the project guide match where things stand today:** eyas-mcp as
  the only MCP server, what the sidecar still holds (56 tools) and how Eyas
  runs Falcon calls through eyas-mcp.
- **MCP server pinned to eyas-mcp 0.21.0 (c034131).** It now identifies itself
  as eyas-mcp in its logs and to clients; no tool names or result shapes
  changed.
- **The update check follows eyas-mcp.** The scheduled release watcher now
  reports when eyas-mcp has commits newer than the version Eyas is pinned to,
  lists them, and says which pin to move. It no longer watches CrowdStrike's
  falcon-mcp releases.
- **MCP server pinned to eyas-mcp bfc9f50.** Closing every open detection on a
  host now also closes the NGSIEM correlation alerts that name only that host,
  so the agent no longer closes them one by one. Alerts that also name other
  hosts are left open and reported; the agent asks before closing those.
- **Incident response's release summary survives busy hosts.** The counts the
  agent needs after closing remediated detections now come first in the
  result, so a host with many detections no longer cuts them off. The
  readiness wait's approval card now explains what it does.
- **Incident response no longer stalls on detections it never touched.**
  After closing what its remediation matched, the agent counts the original
  detections from before the engagement that are still open, which block
  releasing the host. It stops and asks you whether to close them as true
  positive or false positive, or keep the host held. On a close, Eyas closes
  exactly those detections in one approved step. Anything raised during the
  engagement is left alone.
- **Closing every open detection on a host goes through the MCP server.** The
  on-request bulk close (one approval) now uses `eyas-mcp`, and covers open
  detections from every product on the host, not only endpoint detections.
  Incident response still closes only the detections its remediation
  touched.
- **MCP server pinned to eyas-mcp 2703a99.**
- **Incident response waits for the quarantine policy through the MCP
  server.** Before cleanup, Phase 1.5 uses `eyas-mcp`'s readiness wait with
  its script probe: a host counts as ready only once a harmless probe script
  actually runs on it, and the probe is deleted afterwards. If the wait times
  out, the reason for each host is reported. The add-on readiness tool is
  retired.
- **Prevention posture comes from the MCP server.** `/prevention`, the home
  dashboard, Shadow-AI setup and the posture history read `eyas-mcp`'s
  prevention posture, and the chat agent uses it directly. Eyas still flags a
  policy as detect-only only when sensor machine learning or cloud antivirus
  detects without preventing. All policies are now included, not just the
  first 200. Policy descriptions are no longer shown in this view.
- **Patch and cleanup runs go through the MCP server.** Eyas still checks and
  builds every script from its own library (the agent picks a vetted script and
  parameters, never script text), then uploads it as a one-off private script,
  runs it and deletes it with `eyas-mcp`'s RTR tools. Status checks for
  long-running scripts use `eyas-mcp` too. Results look the same as before,
  except that the exit code is no longer reported.
- **MCP server pinned to eyas-mcp 7fd4031.**
- **Discover counts every asset type.** Asset totals come from a single
  all-types search, so assets that are neither managed nor unmanaged (for
  example unsupported devices) count again; the assessment sees them as
  "other types".
- **NGSIEM search runs on the MCP server.** `/ngsiem` uses `eyas-mcp`'s search
  with its query check, a 100-row cap and a 50-second budget that returns
  partial rows instead of timing out. The add-on search tool is retired; Eyas's
  own internal searches keep their checker. The incorrect "regexes must match
  the whole value" rule is gone: CQL regexes match anywhere unless anchored.
- **Incident response captures host groups through the MCP server.** Phase 0
  reads group membership with eyas-mcp's per-group static check (always
  enforced), which still fails the whole call on any error rather than
  dropping a group. The add-on membership tool is retired.
- **Discover runs on the MCP server natively.** `/discover` and the posture
  history read assets, applications and accounts from `eyas-mcp`; the two
  add-on Discover tools are retired. Managed and unmanaged counts are now
  tenant-wide totals rather than counts within a 100-asset sample, so the
  posture history shows a one-time jump in those two lines.
- **Native results with an error are no longer read as data.** A search error
  wrapped with its query guide could show up as one empty row, and a word like
  "unauthorized" in an application name could hide a page as if the scope were
  missing.
- **Fusion workflow reads run on the MCP server natively.** The `/workflows`
  report and the failed-run hand-off use `eyas-mcp`'s definition, execution
  and execution-result tools; running a workflow still goes through the
  approval-gated add-on tool.
- **Recon runs on the MCP server natively.** The `/recon` exposure report,
  the intel dossier's underground-mention counts and the Recon nav check now
  use `eyas-mcp`'s Recon tools; the four add-on Recon tools are retired.
- **NGSIEM searches from `/ngsiem` honour the requested time window.** The
  prompt named the start and end parameters wrongly, so a "last week"
  question could search only the last 24 hours.
- **Retired the add-on NGSIEM provisioning-status tool.** It sent customer IDs
  to an endpoint that takes data connection IDs; `eyas-mcp`'s
  `falcon_get_ngsiem_data_connection_status` does this correctly.
- **Threat Graph runs on the MCP server natively** (first capability migrated
  from the Falcon operations add-on into `eyas-mcp`). Artifact pivots and host
  investigations now list every device that ran a file with when it was seen,
  where the old path returned blank hostname / first-seen / last-seen columns.
  Results are trimmed so a full 50-device page fits without truncation.
- **MalQuery runs on the MCP server natively.** The hash-lineage report's
  corpus table now shows what MalQuery actually returns (label, file type,
  size, first seen) instead of asking for last-seen and family columns it
  never had; family attribution comes from Falcon Intel.
- **NGSIEM data connections, parsers, lookup files and the CQL function
  lookup run on the MCP server natively.** The NGSIEM pipeline strip now shows
  exact totals and a status breakdown across every connection — it previously
  stopped counting at 200 (one tenant: 330 connections, 687 lookup files).
  New: the agent can check a data connection's provisioning status.
- **Hunting guides and queries, Discover accounts, and workflow triggers run
  on the MCP server natively.** Account inventory gains local-admin, failed-
  login and login-location detail. Hunting-guide and trigger listings are
  trimmed for the agent (one guide previously carried ~160 KB of nested
  query and MITRE detail).
- **Threat-actor dossiers include the full report text.** Report and actor
  content now come from the MCP server natively. The previous path read the
  report body from a field Falcon leaves empty, so dossiers were written from
  short descriptions only; they now draw on the full published analysis and
  each actor's kill chain.
- **Identity Protection reads run on the MCP server natively** — risky
  identities, sensor posture, policy rules, user → host history, and the
  host → identity correlation behind the triage queue's identity overlap.
  Identity detections and the identity response workflow are unchanged.
- **Agent toolbox labels native tools `eyas-mcp`** (was `falcon-mcp`); the
  user guides, architecture and demo docs describe the eyas-mcp setup.
- **Host containment runs on the MCP server natively** — every contain and
  lift still requires approval, and incident response still lifts only a
  containment it applied. Verified end to end on a lab host (contained in
  ~10 s, released in ~40 s). A contain covering several hosts now reports
  exactly which ones succeeded.
- **Falcon-published live-response scripts (Process, Service, RegistryKey, …)
  run on the MCP server natively**, still without an approval click (they
  only inspect the host). The agent now sees each script's input fields, so
  parameterized scripts like RegistryKey get called correctly the first time.
- **Multi-host live queries:** the agent can run one read-only live-response
  command across up to 100 hosts in a single step (no approval needed — the
  command set is read-only), instead of opening a session per host.

### Fixed
- **Incident response: a failed containment no longer counts as "contained by
  this workflow."** A containment request that Falcon rejected was still
  recorded as applied, which could let the release step lift a containment
  the workflow never put in place — including on a host that was already
  contained when the response began. Containment now only counts once Falcon
  confirms it for that host.
- The Threat Graph availability check never actually tested the API scope; it
  now does, so `/status` and the scope checklist reflect the real grant.

## 0.9.1 — eyas-mcp 0.20.2

### Changed
- **Upgraded to `falcon-mcp` 0.20.2** (from 0.19.0, spanning 0.20.0–0.20.2).
  Upstream renamed its Data Protection tools to a broader **Data Security**
  module covering ten configuration types (adds cloud and local applications,
  web locations, enterprise accounts, sensitivity labels, and file types). The
  agent can now read all of them; the data-exposure posture page, posture
  history, and setup checks moved to the new tools. The agent can also edit
  existing data-protection configuration (approval-gated); creating new
  configuration still goes through Eyas's monitor-first setup flow.
- **The MCP server is now `eyas-mcp`**, a maintained continuation of
  `falcon-mcp` (which upstream moved to maintenance mode in 0.20.1). Same tool
  surface plus input-hardening fixes; still pinned by git commit. The pinned
  version also adds 33 native tools that re-implement most of the
  Falcon operations add-on; they stay hidden from the agent until each
  capability is migrated, so behavior is unchanged in this release.
- **Builds no longer assume a corporate package mirror.** Dependencies resolve
  from public PyPI / npm by default; a mirror is opt-in configuration.

### Removed
- **In-app update** (the *Update available* badge and `eyas update`). To
  upgrade, download the newer bundle and run its `install.sh` — it replaces the
  installation in place and keeps your password, credentials, and data.

### Fixed
- **Data exposure posture failed on tenants with more than 200 content
  patterns, classifications, or policies on one platform.** It now reads them
  in pages, so large data-protection configurations load in full. Posture
  history no longer records a failed read as "0 content patterns".

## 0.9.0 — Control Center + falcon-mcp 0.19.0 (Guardian / AIDR)

The dashboard becomes an operator **control center**, and AI-agent oversight lands
via falcon-mcp 0.19.0's Guardian module.

### Added
- **Control Center dashboard (`/home`, the post-login landing).** A single
  operate-from-here surface: a **"recommended next move" hero** (deterministic
  triage pick — cross-host campaign → guided IR → triage), then a grouped grid of
  **glanceable capability tiles** (Triage · Ask & hunt · Posture · Operations) that
  each pop a **right-side snack panel**. Detail panels (priority detections,
  cross-host campaigns, contained hosts, prevention gap, IR runs) and **live
  interactive tool panels** (NGSIEM, artifact pivot, recon, MalQuery, daily
  briefing, adversary intel, identity, discover, correlation, spend) run in place;
  every actionable finding hands off to the agent via the existing primer mechanism.
  Backed by a fast deterministic `/api/home/summary` (rank + cross-host campaign
  clustering, no overlays) so it loads on every visit.
- **Global "Ask the agent" chat dock.** A compact agent chat reachable from a
  TopBar button on every page (isolated session, streaming, inline write-approvals).
- **Continue-in-chat from any tool report.** After a capability panel produces a
  report, an in-place follow-up chat (seeded with that report as context) lets you
  interrogate the result without leaving the panel.
- **Guardian / AIDR (falcon-mcp 0.19.0).** The new Guardian module surfaces 25
  read-only AI-agent-activity tools (`AIDR:read`), auto-exposed to the agent. On the
  renamed **AI** page: a deterministic **AI-agent-activity card** (agents / sessions
  / products / elevated Agentic Threat Scores, fetched on load) and a plain-language
  **prompt-inspection** panel (`falcon_search_guardian_prompts`) — plus a one-click
  agentic review. Capability-gated on `AIDR:read`; degrades cleanly when absent.
- **Toast notifications** for transient feedback (copy, env switch, etc.).

### Changed
- **Upgraded to `falcon-mcp` 0.19.0** (from 0.18.0), built from the pinned GitHub
  ref. Tool count 144 → ~169. `guardian` added to the capability probe + scope
  checklist (`AIDR:read`); state doc refreshed. Nothing migrated sidecar → native
  (Guardian is read-only; no writes to gate).
- **Navigation is now a persistent icon rail + hover flyout** (replacing the modal
  drawer) on desktop; the drawer remains for mobile. Nav items are alphabetized
  within each group.
- **App-wide page-header restyle.** The signature reticle graphic (radar sweep +
  corner ticks, page icon at center) + a compact title, propagated through the
  shared `PageHero` to all pages; the big descriptions were dropped. The Control
  Center gets its own bespoke radar header. Dashboard widgets are alphabetized
  within each group.
- **Shadow-AI page relabeled "AI"** (display only — routes, tool names, DB columns,
  env keys, and the canonical "Project Eyas - Shadow-AI Banned" group name are
  untouched contracts). It now covers both unsanctioned AI *tooling* and AI-*agent*
  activity.

### Fixed
- **Chat panel PDF print.** The dock chat now prints/saves cleanly (its own
  `data-print-target` + Print/PDF button + print CSS) instead of dumping the dark,
  fixed-overlay app.
- **Daily-briefing tool hallucination.** The briefing prompt now names
  `falcon_search_vulnerabilities` (+ `facet`) explicitly and rules out the
  nonexistent `falcon_aggregate_vulnerabilities`, so the agent stops guessing an
  aggregate that doesn't exist.
- **NGSIEM CQL Hub link** updated to `https://www.byteray.com/cql-hub`.

## 0.8.15 — falcon-mcp 0.18.0

### Changed
- **Upgraded to `falcon-mcp` 0.18.0** (from 0.16.0, spanning the 0.16.1, 0.17.0,
  and 0.18.0 releases). The agent gains **19 new upstream capabilities**: four new
  Falcon modules — **Zero Trust Assessment**, **Cloud Insights**, **Fusion SOAR
  workflows**, and **AgentWorks** (Charlotte AI agents) — plus native managed-asset
  discovery and Recon aggregation. Every new read is token-bounded; the two new
  write actions (run a Fusion workflow, invoke a Charlotte AI agent) are
  approval-gated like every other write.
- **Faster, more accurate answers to "how many / top-N / distribution" questions
  about Recon** — those now use the new native aggregation tools directly instead
  of paging records by hand.
- Two safety guards Eyas had been applying itself are now enforced upstream in
  `falcon-mcp` (bulk detection updates chunk safely past 1,000 items; invalid
  IOA-exclusion patterns are rejected before submission), so the behavior is now
  consistent whether a write goes through Eyas or the server directly.

### Build
- The standalone bundle now ships a **Node 26** native database prebuild
  alongside Node 22 and Node 24, so it runs on the newest Node LTS.

## 0.8.14 — Shadow-AI cleanup accuracy + reliability polish

### Changed
- **Shadow-AI ban-and-clean now picks the correct uninstaller on its own.** When
  cleaning an AI desktop app off a host, the scan now determines each app's
  install form (Microsoft Store / MSIX vs. a per-user install) and hands the
  workflow the exact uninstall step to run. An MSIX-packaged app is now evicted
  with the right primitive instead of a per-user uninstaller that silently does
  nothing and lets the app reappear at next sign-in. Microsoft Copilot is flagged
  as "managed through policy, not removable here" rather than targeted for an
  uninstall that would never succeed.
- **The Identity Protection page loads faster and more predictably.** Its four
  identity reads are gathered up front in parallel, so the page produces its
  decision document in a single pass — and a tenant without the Identity
  Protection scope gets an immediate, clear "not available" instead of a slow
  partial load.
- **Faster host lookups when planning a patch.** Enumerating the hosts affected by
  a set of CVEs now runs over a single Falcon connection with bounded concurrency
  — measured roughly 1.7× faster on a ~1,000-host fleet — while keeping the same
  permissive fallback so no expected host is dropped.

### Fixed
- **Live-host investigation now runs its real-time commands as intended.** The
  host-investigation posture check was silently skipping its real-time-response
  step; it now opens, runs, and closes the session correctly.
- Several dashboards (detections, at-risk hosts, data protection, triage queue)
  now surface an upstream Falcon error instead of rendering an empty result as if
  it were a clean "nothing found."

### Internal
- Deterministic uninstall routing lives in the Shadow-AI catalog
  (`cleanup_plan`), with an 8-case unit test; the ban-and-clean playbook no longer
  relies on the agent to infer install form from image paths
  (`feedback_deterministic_over_agent_instruction`).
- Added a concrete aggregation example to the chat system prompt.
- Full-surface audit pass (13 clusters, 4 lenses): standardized dashboards on the
  structured `detectFalconError` detector and recorded the
  `isScopeDenied`-on-detection-data pitfall.

## 0.8.13 — Faster vulnerability surfacing

### Changed
- **The Vulnerabilities page loads faster.** Each per-host and global vulnerability
  fetch now pulls CVE detail, host info, and remediation in a **single** Spotlight
  query instead of three separate ones merged together — roughly halving the
  round-trips on a fleet sweep. Same data, fewer calls. (Uses falcon-mcp's
  list-facet support, already used by the scorecard and patch digest.)
- **The Triage Queue** resolves its detections and adversary attributions over a
  single Falcon connection per request instead of opening two.

### Internal
- Opt-in shared-connection mode for the host-investigation fan-out (default off,
  soaking) — a live probe confirmed it's safe and faster for that path, while the
  vulnerability fan-out keeps its multi-connection model (measured faster there).
- Refreshed the maintainer-facing `falcon-mcp` state report to 0.16.0.

## 0.8.12 — Aggregation tools + 0.16.0 reconciliation polish

### Added
- **The agent now uses falcon-mcp 0.16.0's aggregation tools for "how many / top-N /
  distribution / trend" questions** — counts of detections by severity, tactic, host,
  or status, distinct-host counts, volume over time, and case-configuration counts —
  instead of paging and hand-counting records. One aggregate call returns the buckets.
  The six new aggregate reads are exposed with non-lossy, bucket-capping projections.
  (`lib/mcp/projections.ts`, `app/api/chat/route.ts`)

### Changed
- NGSIEM search now points the agent at 0.16.0's CQL authoring guide, surfaced
  alongside the FQL filter guides and correctly labelled as CQL (not FQL).
- Refreshed the internal falcon-mcp vs. FalconPy comparison notes for 0.16.0
  (concurrent request handling and NGSIEM CQL guidance now come from the MCP server).

### Fixed
- Repointed a stale reference to a non-existent `falcon_get_actor_details` tool at the
  real `extras_intel_actor_profile` (the Intel exposure report prompt and a hunt
  docstring).

## 0.8.11 — falcon-mcp 0.16.0

### Changed
- **Upgraded the bundled falcon-mcp server from 0.14.0 to 0.16.0.** 0.16.0 adds
  concurrent request handling, NGSIEM CQL authoring guidance, alert/case
  aggregation tools, and a host grouping-tag management tool. Pinned via commit
  SHA in `versions.json`; verified it resolves through the offline wheel path.

### Fixed
- **Search views render correctly under falcon-mcp's new pagination envelope.**
  falcon-mcp 0.15.0 began wrapping every search tool's response in a
  `{ results, pagination }` object instead of a bare list of rows. The console now
  unwraps that envelope, so the Detections, Hosts, Cases, Vulnerabilities, Intel,
  and Queue views — and the agent's own search tools — return real records again
  instead of a single empty row. Guarded so it never misfires on error or
  scope-denied responses. (`lib/mcp/parse.ts`, covered by `test:parse`)

### Added
- **Approval-gated the new `falcon_manage_host_grouping_tags` write** (grouping
  tags can drive dynamic host-group and policy assignment, so it changes posture).
  The six new read-only aggregation tools (alert + case-configuration counts)
  auto-expose to the agent.
- Trimmed the ~4 KB CQL authoring guide that 0.16.0 echoes on empty NGSIEM
  searches, and hardened the server spawn so stray `FALCON_MCP_*` read-only /
  tool-filter / dynamic-mode environment flags can't silently reconfigure it.

## 0.8.10 — Finished-intelligence depth + the deterministic Dossier

### Added
- **New `/intel-dossier` surface (Hunt group).** Enter a threat actor, campaign,
  or keyword and it fans out **server-side, every run** — pulling the full
  finished-intelligence report bodies, full actor profiles, and the Recon
  underground footprint — then writes a decision-document dossier (verdict / who
  they are / activities & tradecraft / victimology / underground presence /
  assessment / sources). Deterministic enrichment: the depth never depends on the
  model choosing a tool. Files: `app/intel-dossier/page.tsx`,
  `app/api/intel-dossier/route.ts`.
- **Two finished-intelligence tools.** `extras_intel_report_content` returns the
  full published report body (not just the one-line search summary), and
  `extras_intel_actor_profile` returns the full actor narrative — aliases,
  targeting, capabilities, objectives. These surface the depth that
  `falcon_search_reports` / `falcon_search_actors` omit, under the same Falcon
  Intelligence scope. The chat agent now fetches this depth after a report/actor
  search instead of stopping at the summary. Files: `falcon-extras/intel.py`,
  `app/api/chat/route.ts`.

## 0.8.9 — Blueprint: a developer "build-your-own" advisor

### Added
- **New `/blueprint` Reference surface** — a developer-facing advisor that
  explains how to build an agentic SOC on falcon-mcp, FalconPy, and Claude.
  Pick a seeded blueprint (or ask your own question) and it streams a build
  analysis grounded in this console's own reference architecture — the
  in-process MCP client + tool-use loop, approval-gating, the falcon-mcp↔
  FalconPy split, deterministic enrichment — with an **Authoritative sources**
  panel that links out to `developer.crowdstrike.com` for the platform
  primitives. Sits in the Reference nav group beside Agent toolbox: where Agent
  toolbox shows *what* tools the agent composes, Blueprint shows *how*. Works
  with only Anthropic configured (no Falcon dependency). Files:
  `app/blueprint/page.tsx`, `app/api/blueprint/route.ts`,
  `components/BlueprintAdvisor.tsx`, `lib/advisor/`.

## 0.8.8 — falcon-mcp 0.14.0 + single-call Spotlight facets

### Changed
- **Bundled falcon-mcp upgraded 0.13.0 → 0.14.0** (additive; nothing removed or
  renamed). Three new read-only cloud tools — `falcon_search_cloud_risks`,
  `falcon_search_cloud_groups`, `falcon_get_cloud_groups` — auto-expose to the
  agent on tenants licensed for Cloud Security. No new write tools.
- **Spotlight vulnerability lookups now use a single multi-facet call.** 0.14.0
  lets `facet` take a list, so `lib/posture/snapshot.ts` and
  `lib/scheduler/patch-digest.ts` hydrate CVE + host + remediation detail in one
  Spotlight query instead of two or three fanned-out calls merged by id — fewer
  round-trips and less pressure on the ~5000-row Spotlight timeout. Confirmed the
  combined endpoint returns every requested sub-object per record.
- **Result ordering on the two-step search tools** (`falcon_search_detections` /
  `_hosts` / `_iocs`) is now restored upstream; dashboards keep their client-side
  re-sort as harmless defense.

### Security
- **Minimum `cryptography` raised to `>=48.0.1`** to incorporate the fix for
  CVE-2026-34180, kept below 49 for a package-mirror layout constraint.

## 0.8.7 — /status "setting up" state on first launch

### Changed
- **`/status` no longer shows a red error while the offline components are still
  installing on first launch.** After a fresh install or an update, `start.sh`
  builds the bundled Python environments before serving; if a health probe runs
  during that window (or a stale pre-reinstall server had its environment removed
  out from under it), the spawn fails with `ENOENT`. That now maps to a new
  amber **"setting up"** state — header reads *"Setting up…"*, the probe rows
  show a `setup` badge with *"Finishing first-time setup — installing components.
  This usually takes under a minute; reload shortly,"* and the Falcon operations
  add-on card shows an amber setup panel — instead of a red "Degraded"/error that
  reads as broken. Detection is a spawn `ENOENT` **while the bundle's vendored
  wheels are present**; a genuine missing-binary error (dev, no wheels) stays a
  red error. `/api/health` `overall` can now report `initializing` too. Files:
  `lib/health.ts` (new `initializing` `ProbeStatus` + `isFirstLaunchSetup`),
  `app/status/page.tsx`, `app/api/health/route.ts`.

## 0.8.6 — Fix: standalone bundle dropped sidecar subpackages

### Fixed
- **IR quarantine + Shadow-AI setup cards showed "Couldn't read tenant state"
  on the standalone bundle.** The bundler flattened every falcon-extras
  subpackage (`ir/`, `shadow_ai/`, `ngsiem/`, `patching/`, `process_tree/`,
  `cleanup/`) into the sidecar root instead of shipping them as directories, so
  the setup-card tools' lazy `from ir.provision_quarantine import …` raised
  `ModuleNotFoundError` at call time and the route reported "sidecar returned
  non-JSON". Root cause: `make-dist.sh` copied each package with a trailing
  slash (`cp -R falcon-extras/ir/ dest/`), which on macOS/BSD `cp` copies the
  *contents* rather than the directory. Now copies `"${d%/}"`. Introduced by the
  `d402ab7` auto-discovery refactor; affected v0.8.4–v0.8.5.
- **`expected_tools.json` now ships deterministically.** The top-level staging
  `find` only matched `*.py`/`requirements.txt`; it now also copies `*.json`, so
  the file the build-time verifier and `/api/health` depend on is always present.

### Added
- **Build-time guard against dropped sidecar packages.** `verify_tools.py` now
  parses `server.py` and resolves every module a tool body lazily imports, so a
  flattened/dropped cluster package fails the build instead of shipping a bundle
  that `ModuleNotFoundError`s at runtime. (Registration alone couldn't catch it —
  `import server` never fires the lazy tool-body imports.)

### Changed
- **Sidecar tool errors now surface the real cause.** `parseExtrasObjectResult`
  (`lib/mcp/parse.ts`), wired into the IR/Shadow-AI diagnose + adopt routes,
  echoes a truncated slice of a raised sidecar tool's actual error text (e.g.
  `ModuleNotFoundError: No module named 'ir'`) instead of the opaque "sidecar
  returned non-JSON", so the /config cards and the chat agent get a legible
  failure to reason about.

## 0.8.5 — Streamlined install + in-app updates

### Added
- **Named-command install + one-click updates for the standalone bundle.** The
  macOS bundle now ships an `install.sh` that installs a named `eyas` command to
  `~/.local/bin` (`eyas` / `stop` / `restart` / `status` / `logs` / `update`) and
  copies the app into `~/.local/share/project-eyas`. The end-user flow becomes
  download → extract → `bash install.sh` → `eyas`. A new top-bar **Update
  available** pill polls the distribution repo and offers one-click **Update
  now**, which downloads the latest bundle, re-installs in place, and restarts —
  preserving credentials and the database (`.env` + `data/` are excluded from the
  update). `eyas update` does the same from Terminal. Backed by
  `/api/update/{check,apply,status}` and `components/UpdateBadge.tsx`; the
  approach mirrors the shared `macos-standalone` method but keeps eyas's bespoke
  `make-dist.sh` (native better-sqlite3, Python sidecar, baked gateway lock). See
  `SECURITY.md` → *In-app update surface*.
- **`standalone.json`** at the repo root — single source for the app/command
  name, default port, and the distribution-repo coordinates the
  installer, launcher, and update check all read. `scripts/gen-install.sh`
  generates the bundle's `install.sh` from it at build time.

### Changed
- **`make-dist.sh`** now stages `standalone.json` and generates `install.sh` into
  the bundle; the closing instructions lead with the `install.sh` / `eyas` path
  (`./start.sh` remains a foreground fallback).
- **`start.sh`** skips its own browser-open under the managed launcher
  (`EYAS_MANAGED=1`) so `eyas start` owns readiness + browser-open without a
  double-open; the foreground `./start.sh` path is unchanged.
- **Distribution:** the release zip is now hosted as a download alongside the
  user guide; the in-app updater pulls from the distribution repo.

## 0.8.4 — Approval-gate hardening + falcon-mcp signal consumption

### Added
- **Annotation-backed approval-gate backstop.** falcon-mcp 0.13.0 marks every
  write tool with MCP annotations (`readOnlyHint: false`), and the console now
  consumes them: any native tool that advertises a mutation but is missing from
  the explicit approval registry is still approval-gated (fail-closed) and
  logged as an `APPROVAL DRIFT` line, so a write added in a future falcon-mcp
  version can't slip through un-gated before someone lists it. The
  `/agent-toolbox` reference page surfaces an amber "approval-gate drift" banner
  if that ever happens (empty in the normal state). RTR session / read-only
  command tools are explicitly exempt — they advertise a write but are
  deliberately un-gated so live-host investigation doesn't demand an approval
  click per command. The `audit-write-tools` check verifies the wiring stays in
  place.

### Changed
- **Scope-denial detection now keys on the structured error, not prose.**
  falcon-mcp packages a permission denial as an `{error, details}` payload with
  a `status_code` and, for a recognized 403, a `required_scopes` list. Detection
  previously matched the literal phrases "scope not permitted" / "access denied"
  — which falcon-mcp 0.13.0 no longer emits for a 403 (its message is
  "Permission denied. The API credentials don't have the required access."), so
  a real denial could read as an empty page instead of a staged-build banner.
  A shared `isScopeDenied` helper now keys on the status code / required-scopes
  signal (with the old phrases kept as a fallback), used by the nav capability
  probes and the Cases / Quarantine / Correlation / Data Protection surfaces
  alike.
- **Agent tool results parsed per content block.** The agent path now parses
  each MCP result block directly instead of joining every block into one string
  and re-deriving the boundaries — the block-aware path the MCP SDK's
  one-object-per-row serialization intends, with a per-block fallback so it
  stays at least as robust as before.

### Docs
- Added internal notes on where the console relies on the FalconPy sidecar vs.
  native falcon-mcp tools (not part of the public repository).

## 0.8.3 — Shadow-AI IOA enforcement fix + configurable chat output limit

### Fixed
- **Shadow-AI Custom IOA prevention now actually blocks.** The adoption flow
  had two latent defects that left the rule bundle inert even though the rule
  group and prevention policy showed enabled: every individual rule was created
  **disabled** (Falcon creates Custom IOA rules disabled, and only the rule
  *group* was being enabled — never the rules), and the disposition constants
  were off by one notch against the live ruletype map, so "block" mode set
  **Detect** (20) and the real process-kill disposition (**30 = Block
  Execution**) was never used. Adoption now corrects the constants
  (Monitor=10 / Detect=20 / Block=30), defaults to block, enables the rules,
  and **converges existing rules** on re-run — a read-modify-write that
  preserves each rule's live match patterns, so a previously-broken ruleset is
  repaired in place and the detect↔block flip actually works. `dry_run` returns
  the full create/converge plan.

### Added
- **Configurable chat output limit.** The per-turn output-token cap for the
  `/chat` surface is now editable in `/config` (Anthropic card) instead of a
  hardcoded value — raise it when long scripts or answers get truncated, lower
  it to cap per-reply cost. Range 1,024–64,000; default 16,384.

## 0.8.2 — falcon-mcp 0.13.0: native Recon reads

### Changed
- **Upgraded falcon-mcp from 0.12.0 to 0.13.0.** This adds CrowdStrike's native
  Falcon Intelligence Recon module — three read-only tools
  (`falcon_search_recon_rules`, `falcon_search_recon_notifications`,
  `falcon_search_recon_exposed_data_records`) the agent now reaches directly,
  each token-bounded by a projection that mirrors the existing sidecar Recon
  shape (the exposed-records projection deliberately omits the raw leaked
  credential value, surfacing only exposure metadata). The four sidecar
  `extras_recon_*` tools stay in place: the `/recon` exposure report calls them
  by name, the capability gate probes one of them, and the corpus-aggregate
  search (`extras_recon_preview_corpus_search`) has no native equivalent. No new
  write tools shipped; per-tool approval gating is unchanged. Dynamic mode is
  deliberately NOT enabled — it would route the whole tool surface behind a
  dispatch tool and bypass per-tool approval gating.

### Fixed
- **`falcon_remove_iocs` now returns a deletion summary** (`{status,
  deleted_ids, count}`) on success instead of an empty body. The empty body
  previously surfaced a benign upstream response-model parse error on an
  otherwise-successful delete; the Shadow-AI playbook's workaround note for that
  quirk has been removed.
- **Detection verdicts now write the literal `true_positive` / `false_positive`
  tag** instead of the legacy `FalconUITagged*` prefix. The prefix was an old
  `/detects` (v1/v2) UI-tag convention that the v3 Alerts experience dropped;
  the fabricated `FalconUITaggedTruePositive` value matched neither what the
  Falcon console writes when an operator sets a verdict nor (almost certainly)
  the coverage rollups. Confirmed against falcon-mcp 0.12.0's native passthrough
  and a read-only probe of live tenants (console-applied verdicts carry no
  prefix). The approval-gated `extras_update_detection_status` /
  `extras_ir_close_remediated` path is otherwise unchanged and remains the
  verdict writer — it adds force-close, 500-id chunking, and audit comments the
  native tool lacks.

## 0.8.1 — Reliable IR host-group membership capture

`extras_host_group_membership_for_device` is the authoritative source for a
host's original group membership in IR Phase 0 — the list Phase 4 restores from.
It resolves membership by walking every host group in the tenant and probing
each one for the AID, because the `groups` array on the host record omits
dynamic-group memberships and lags static ones. Run serially, that `1 + N` walk
crossed the agent tool transport's 60-second request ceiling on tenants with
enough host groups, and the timeout surfaced as a hard failure that broke Phase
0 capture.

This release fans the per-group probes out concurrently, so wall time stays
bounded regardless of group count — without changing what the walk returns or
weakening its guarantees.

### Fixed
- **IR host-group membership capture no longer times out.** The per-group
  membership probes now run concurrently (bounded worker pool, one shared
  authenticated client, per-request timeout to bound a single hung connection),
  collapsing a sequential `1 + N`-call walk that exceeded the 60-second
  transport ceiling on multi-group tenants to roughly one round-trip. The
  authoritative-list contract is unchanged: a permission or upstream error on
  any probe still fails the whole call loudly rather than silently dropping a
  group, which would leave a host un-restored in Phase 4.

## 0.8.0 — Generic Windows installer + runtime patch extensibility

The curated patch-script library is baked into the bundle. That is the security
spine — the agent picks a script `id` and supplies validated params; it never
authors script bytes. But it also means a consumer of the standalone bundle hits
a wall the moment a vulnerability needs an app the library never shipped a
per-app script for. Editing the manifest and rebuilding is a developer-only loop,
not something an operator on a distributed build can do.

This release lets a consumer close that gap at runtime, with no rebuild, without
weakening the boundary: one generic Windows installer whose bytes stay baked,
parameterized at runtime. Successful parameter-sets can be saved as per-tenant
patch profiles — the consumer builds their own catalog at runtime as data, never
bytes — and `/vulnerabilities` surfaces the coverage gap so it is discoverable,
not just emergent in chat. It deliberately does not add a runtime store of
arbitrary script bytes; novel logic the generic engine can't express is out of
scope (it belongs in the consumer's own Falcon custom-scripts store).

### Added
- **Generic Windows installer (`win-app-install`).** A single manifest entry that
  installs or upgrades a Windows app from a vendor HTTPS URL, parameterized at
  runtime: `url`, optional `sha256`, `kind` (msi/exe), optional `silent_args`
  (exe-only), `product`. Declared last in the manifest and carrying no
  `spotlight_match`, so it can never shadow a specific app script — it is reachable
  only by explicit invocation.
- **Per-tenant patch profiles.** Save a validated parameter-set as a reusable
  named source (`extras_save_patch_profile`) and list saved profiles
  (`extras_list_patch_profiles`). Stored per-environment as data
  (`patch_profiles` column, migration `0008`); no Falcon-side object, no script
  bytes.
- **Capability-gap discoverability on `/vulnerabilities`.** A server-computed
  badge marks Windows remediations no curated script covers, alongside
  generic-installer and save-as-profile hand-offs. Curated Build-plan / Run
  affordances are unchanged for remediations a specific script does cover.

### Security
- **The render-time boundary is unchanged.** The agent supplies a validated `id`
  plus params and never script bytes. The manifest param-regex is a positive
  allowlist (bans whitespace, quotes, backtick, and shell metacharacters); values
  render as inert single-quoted PowerShell literals; unknown keys fail closed.
  `extras_rtr_run_patch` exposes no byte-accepting parameter — the agent cannot
  author freehand PowerShell regardless of how it is prompted. The generic
  installer is parameterization, not a script factory.
- **SHA-256 is the integrity gate.** A pinned hash is verified host-side before
  install (`Get-FileHash`, case-insensitive) and aborts on mismatch with a
  dedicated exit code before any install runs. Omitting it proceeds behind a loud
  `UNVERIFIED (no hash pin)` banner, surfaced to the operator as a structured
  `hash_pinned` signal on the dry-run preview so the approval is conscious. HTTPS
  + dry-run-first + the existing write-approval gate remain the fallback.
- **Saving is approval-gated.** `extras_save_patch_profile` is in the
  approval-gated registry — establishing a trusted reusable source is a conscious
  decision distinct from running a patch.

## 0.7.1 — Agent toolbox + IR release-safety hardening

Two threads. First, a developer-facing reference surface that renders, on one
screen, the exact set of Falcon tools this console's agent can compose — the live
`falcon-mcp` tool list plus the FalconPy extension — each marked read-only or
approval-gated, with its JSON input schema. Until now that surface was visible
only implicitly through chat tool-call traces. It is the counterpoint to building
agents one at a time: a single bring-your-own-AI loop sees the *entire* live tool
catalog.

Second, the load-bearing safety invariants of the agentic IR workflow move from
prompt prose into code. An adversarial audit (four skeptic personas — security
analyst, developer, IR analyst, CISO) found that the workflow's highest-blast-radius
guarantees — "don't lift containment this workflow didn't apply," "don't release a
host while real threats remain," "don't close a detection nothing actually
remediated" — were enforced only by the system prompt and playbook text. A
misread prompt, or a prompt-injection riding in an unscanned tool result, could
defeat any of them. This release adds deterministic, server-side backstops at the
tool-call seam that the agent cannot talk its way past.

### Security
- **Containment-lift backstop (F1).** A server-side guard at the tool-call seam
  refuses `extras_host_lift_containment` / `extras_host_group_remove_members` for
  the IR target host when the engagement did not itself apply containment —
  derived authoritatively from the `ir_run_turns` audit (an allowed, non-errored
  `extras_host_contain` this run), never from the agent's advisory flag. A host
  contained before the engagement (or by another actor) is the operator's to
  release from the Falcon console, not the workflow's. The guard is *additive* —
  it can only block, never bypass the existing write-approval gate — and throws
  fail closed (the host stays contained).
- **Deterministic release gate (F2b).** Before the same release writes, the guard
  runs the existing deterministic `extras_ir_phase3_verification_scope` against
  the run's kickoff time and blocks release while any genuinely new detection
  fired during the engagement remains open, or while any of the *exact* Phase-0
  original detections still carries an open status (re-hydrated by `composite_id`,
  no time filter). "Resolved" now means re-checked-and-not-open, not "the
  remediation call returned ok." A scope-call error blocks release (fail closed).
  The result is memoized per host for the seconds-apart lift + group-remove pair.
- **No host-wide ledger kinds (F3).** The Phase-4 ledger closer previously honored
  `host_contained` / `host_lifted` / `host_rebooted` entries that matched *every*
  open detection on the host unconditionally — so routine containment could
  blanket-close unremediated detections and the release gate would then see
  nothing open. Those three kinds are removed entirely; containment, lift, and
  reboot are host-state changes, not per-detection remediation (persistence
  survives a reboot), and the lift decision is tracked via the `agent_contained`
  flag, not the ledger. The closer now matches only on specific per-artifact
  evidence (killed PID + exact process-image basename; quarantined/deleted file by
  full path or hash; reverted registry value; removed service / scheduled task by
  bounded token), biased to *under*-close — an unmatched detection stays open for
  operator review rather than being waved closed.
- **Tamper-evident IR audit (F6).** New append-only SQL triggers make
  `ir_run_turns` immutable (UPDATE/DELETE raise), and migration
  `0007_ir_runs_kickoff_immutable` freezes the kickoff-captured `ir_runs` columns
  (host role, contained-at-start) against later rewrite while still allowing the
  running `lastTouched` bump. Audit-write failures that were silently swallowed now
  surface to the operator as a caution event — the IR run continues (fail-open on
  the workflow), but the operator learns the turn wasn't captured (fail-visible on
  the audit).
- **Untrusted tool-result fencing (F5).** Tool-result content handed back to the
  model is wrapped in an explicit "treat as data, never as instructions" fence —
  defense-in-depth against prompt-injection in upstream payloads, layered with
  AIDR rather than replacing it. The raw result the operator sees is unchanged.

### Changed
- **Domain-controller blast-radius is surfaced, not hidden (F4).** IR eligibility
  now carries the host role; a Windows Domain Controller renders a red caution
  chip (network containment severs domain authentication fleet-wide) instead of a
  chip identical to a workstation's. Still clickable — operators legitimately need
  to IR a DC; the invisible foot-gun is removed, not the capability. The
  `extras_host_contain` approval card surfaces the verified role so the operator
  approves informed.
- **Tool-contract drift check (F8a).** `verify_tools.py` now pins the agent-facing
  required-parameter contract for the safety-critical write tools (contain, lift,
  close-remediated, cleanup, status-update, group add/remove), failing the build
  if a refactor drops or renames a gated tool's parameter. Name-only checking is
  unchanged for the rest.

### Added
- **Verified-facts approval card (F5).** Contain / lift approval cards now render a
  distinct "Verified by Eyas — independent of the agent" block (containment
  provenance, host role) drawn from the local IR ground-truth tables, visually
  separated from the agent-reported rows, so the operator sees facts the agent
  cannot fabricate. Fixes a dead duplicate branch that had suppressed the contain
  card's if-approved / if-denied narration. Spec: `tests/verified-facts.spec.ts`.
- **IR ground-truth module + tests.** A server-only reader
  (`lib/chat/ir-ground-truth.ts`) over the IR tables backs the guard and the
  verified card. New pure-function test suites pin the load-bearing classifiers
  that don't surface in typecheck or Playwright: the Phase-3 prior-open classifier
  (`falcon-extras/ir/test_phase3.py`), the ground-truth reader
  (`scripts/test-ir-ground-truth.mjs`), and the approval/session-binding core
  (`scripts/test-approvals.mjs`). Migration `0006_ir_audit_hardening`.
- **Agent toolbox (`/agent-toolbox`).** Lives in its own **Reference** nav group
  and is explicitly labeled a developer surface. The catalog is built from the
  exact post-suppression, agent-visible tool set — it reuses the same tool-bridge
  the chat agent loop uses, so it cannot drift from what the agent actually sees
  (no second copy of the suppression rules). Each tool row shows its provider
  (`falcon-mcp` vs. extension), a read-only / approval-gated chip, top-level
  parameters, and a full JSON input-schema disclosure; a search box plus
  provider / access filter chips narrow the list. A "why are some native writes
  not shown?" disclosure lists the native writes deliberately routed to richer
  curated equivalents (so their pre-write safety checks — IOA regex validation,
  canonical host-group naming, disable-before-delete, verdict-tag
  canonicalization — aren't lost), making the curation story explicit.
  **Read-only by design** — the page never invokes a tool, so it stays off the
  write-approval, cost, and FQL-injection paths entirely; chat remains the only
  place tools actually run, behind the approval gate. New read API at
  `/api/agent-toolbox-catalog` (TTL-cached, `?force=1` to rebuild). Degrades to a
  calm "connect a Falcon tenant" note when the catalog can't build. Spec:
  `tests/agent-toolbox.spec.ts`.

## 0.7.0 — operator-console surfaces: posture history, SOC scorecard, incident reports

Three net-new surfaces that answer the question a prospect coming from the Falcon
console can't answer from a dashboard alone: *what has this console actually done
for my tenant, and where is my posture heading?* All three follow the house
pattern — deterministic aggregation server-side (pure functions, no upstream
calls), with agentic synthesis only on explicit operator request.

### Added
- **Posture-history snapshots.** A recurring scheduled capture records a
  point-in-time readout of the active tenant's posture across seven categories —
  detections, vulnerabilities, asset/account coverage, identity, prevention
  policy, data protection, and cases — into a new `posture_snapshots` table
  (metrics stored as JSON, so new metrics need no migration). Each category is
  captured independently: a missing scope or upstream error nulls only its own
  metrics and flags the snapshot `partial`, rather than failing the whole
  capture; an all-empty capture is not persisted, keeping the trend clean.
  `/status` gains a **Posture history** card showing the latest capture time,
  how many snapshots are stored, coverage, and the movement between the two most
  recent captures. New read API at `/api/posture/snapshots`. Migration
  `0004_posture_snapshots`.
- **Agentic SOC scorecard (`/scorecard`).** A leadership-readable readout of what
  this console has accomplished for the active tenant — incident-response
  engagements run (with median/mean close time and detections resolved), gated
  write actions reviewed / allowed / declined / expired, breadth of agentic work
  by surface, and posture movement — each computed deterministically from the
  local ledgers with a period-over-period read (the trailing window vs the window
  before it). Pure local-DB aggregation: no LLM, no upstream Falcon calls. New
  read API at `/api/scorecard`.
- **Incident-report generation (from IR engagements).** Any incident-response
  engagement on `/ir-runs/<engagement>` gains a one-click **Generate incident
  report** action that streams a layered report: a plain-language executive
  summary for leadership on top, full technical detail below (timeline, affected
  host, response actions by phase, detections & evidence, human oversight, open
  items, recommendations). The factual substrate is the frozen engagement record
  (the existing deterministic IR-analysis extractors — zero re-derivation); the
  prose is synthesis-only — the model is given no tools and makes no upstream
  Falcon calls, so the report is fast, cannot fail on an upstream error, and
  reflects only what the engagement actually captured. Internal tool and script
  identifiers are translated into plain operator language in the output. Print /
  PDF + send-to-webhook capture, same as the daily briefing. New route
  `/api/ir-report`.

### Changed
- **Engagement and cost ledgers are now environment-scoped.** `cost_log` rows and
  IR engagement records are stamped with the environment (tenant) they ran under
  (migration `0005_ledger_env_id`), so the scorecard and incident reports
  attribute cleanly per tenant in a multi-environment deployment and never blend
  two tenants' numbers. Rows written before attribution existed (`env_id` NULL)
  are excluded rather than cross-counted — an honest under-count beats
  cross-tenant contamination. Cost attribution resolves the active environment in
  its own guarded step, so a settings hiccup downgrades a row to unattributed
  rather than dropping the cost entry entirely.

### Security
- **The incident-report and posture surfaces enforce the active-tenant boundary.**
  The incident-report route refuses to generate for an engagement that ran under a
  different tenant than the active one (returns not-found rather than rendering
  another tenant's record), and rejects request keys containing path separators.
  The synthesis-only agent loop is given no tools, so a report generation can make
  no Falcon writes or reads regardless of what the engagement record contains.

## 0.6.7 — native write reconciliation: adopt the safe primitives, retire redundant twins

### Changed
- **Five native falcon-mcp 0.12.0 write tools are now the agent's primary write
  path** (un-suppressed at the bridge, still approval-gated):
  `falcon_delete_exclusions`, `falcon_update_host_group`,
  `falcon_delete_host_groups`, `falcon_update_policy`, and
  `falcon_perform_policy_action`. Each either has no FalconPy twin — the
  `update`/`perform` tools are net-new capability the sidecar never offered — or
  only a thin by-id delete twin, so exposing native adds reach without regressing
  any curated behavior. They stay in `REQUIRES_APPROVAL`, so each still pauses for
  operator approval before firing: exposed-and-gated, exactly like the upstream
  `falcon_*` writes.
- **Retired three redundant FalconPy sidecar tools** now that native by-id delete
  covers them: `extras_delete_ml_exclusion`, `extras_delete_ioa_exclusion`, and
  `extras_delete_host_group`. These were thin wrappers over a single delete call
  with no pre-flight or canonical-naming value-add. Tenant teardown is unaffected —
  it calls the FalconPy host-group / exclusion delete collections directly, not
  these tool wrappers. (`extras_delete_prevention_policy`, which disables before
  delete, and `extras_delete_ioa_rule_group` are kept.)

### Security
- **The remaining eight native 0.12.0 writes stay suppressed and routed to their
  curated FalconPy twins** — adopting them would silently regress behavior a native
  tool can't reproduce: `falcon_update_detections` (twin writes the canonical
  `FalconUITaggedTruePositive` / `FalconUITaggedFalsePositive` verdict tags that
  drive Spotlight/MITRE rollups; native writes a literal `true_positive` string),
  `falcon_create_exclusion` (twin runs the IOA zero-width-assertion + single-quote
  pre-flight locally), `falcon_create_host_group` / `falcon_create_policy` (twins do
  canonical naming + same-turn runtime-id override + `{ok,id}` auto-save),
  `falcon_perform_host_group_action` (twin runs the dynamic-group pre-flight; IR and
  Shadow-AI playbooks call the add/remove-members twins by name),
  `falcon_delete_policies` (twin disables before delete — Falcon rejects deleting an
  enabled policy), plus `falcon_update_exclusion` and `falcon_set_policy_precedence`
  (no twin; held back as unguarded-regex-update and fleet-wide-blast-radius). A
  native tool has only three interception points — bridge suppression, a binary
  approval gate, and post-result processing — with no pre-write or in-sidecar hook,
  so a twin's pre-write value-add cannot be re-injected onto a native path; the only
  way to preserve it is to keep routing to the twin.
- **All 13 native writes remain in `REQUIRES_APPROVAL`.** `/audit-write-tools` now
  enforces a two-category invariant: the 8 suppressed writes must be both suppressed
  and gated, the 5 adopted writes must be gated and *not* suppressed, and the two
  lists must stay disjoint. No native Falcon write path is reachable un-gated.

## 0.6.6 — falcon-mcp 0.12.0 reconciliation

### Changed
- **Upgraded the bundled falcon-mcp server to 0.12.0** (from 0.11.0). The release
  adds native `detections`, `host_groups`, `exclusions`, and `policies` modules.
  The six net-new **read** tools — `falcon_search_host_groups`,
  `falcon_search_host_group_members`, `falcon_search_exclusions`,
  `falcon_get_certificate_details`, `falcon_search_policies`, and
  `falcon_search_policy_members` — are now exposed to the agent, each token-bounded
  by a projection that drops the heavy settings / assignment-rule blobs (group and
  policy member reads reuse the slim host projection). The chat system prompt nudges
  the agent to prefer the curated `extras_prevention_policy_posture` read for
  posture questions and use `falcon_search_policies` only for id lookup / enablement
  / listing the hosts a policy governs.

### Security
- **All 13 native write tools are suppressed at the tool bridge and never reach the
  agent.** falcon-mcp 0.12.0's detections / host-group / exclusion / policy writes
  are routed instead to the richer FalconPy sidecar twins (canonical
  `FalconUITaggedTruePositive`/`FalconUITaggedFalsePositive` verdict tags that drive
  Spotlight/MITRE rollups, IOA zero-width-assertion pre-flight, canonical-naming +
  auto-save provisioning). The same 13 names are also listed in `REQUIRES_APPROVAL`
  as a fail-closed backstop — if a future refactor un-suppresses one, it pauses for
  approval rather than auto-firing. `/audit-write-tools` now asserts every native
  write is *both* suppressed and gated, and flags drift in either direction. No
  native Falcon write path is reachable un-gated.

## 0.6.5 — Fable 5 audit remediation + conversation drawer

### Security
- **Login cookie `Secure` attribute now keys off the request scheme, not
  `NODE_ENV`.** The standalone bundle runs `NODE_ENV=production` over plain HTTP
  (`http://127.0.0.1:3000`), where a `Secure` cookie is silently dropped — which
  would have logged the operator out on rolling-renewal. Both `lib/auth/session.ts`
  and `middleware.ts` now derive `Secure` from `x-forwarded-proto`: any
  TLS-terminating reverse proxy sets the header so real HTTPS deploys keep
  `Secure`, and only direct-HTTP localhost relaxes it.
- **FQL injection hardened on identity endpoint-history lookup.** The
  agent-supplied `sam_account_name` (`extras_identity_endpoint_history`) is
  interpolated into a single-quoted FQL literal; it is now rejected up front if it
  contains an apostrophe or backslash, closing a filter-injection path. AD
  samAccountNames never contain these characters, so a hard reject is safe.

### Changed
- **Chat conversation list is now a pop-out drawer at every breakpoint.** Previously
  a persistent left rail on desktop, the conversation history (`ConversationList`)
  now overlays the chat as a dismissible drawer at all viewport sizes, opened by a
  Gemini-style toggle anchored at the chat column's top-left (backdrop / X / New
  all close it). The chat surface stays full-width and bare until the operator asks
  for history. Covered by `tests/chat-conversation-drawer.spec.ts`.
- **Standalone bundle is now Apple-Silicon-only.** `make-dist.sh` stages only the
  `darwin-arm64` better-sqlite3 prebuilds (the fleet is fully arm64); an Intel Mac
  would `ENOEXEC` at launch. Re-add `darwin-x64` to `BSQLITE_TARGETS` if that fleet
  returns. Bundle also prunes `test_*.py` from the sidecar (dev-only).
- **Pinned sidecar runtime + relaxed compose tenant creds.** `requirements.txt`
  pins exact versions (`crowdstrike-falconpy==1.6.2`, `mcp==1.27.0`).
  `docker-compose.yml` makes per-tenant Falcon creds + `ANTHROPIC_API_KEY` optional
  (the app reads tenant credentials from the encrypted DB), keeping only
  `AUTH_SESSION_SECRET` + `FALCON_MCP_API_KEY` hard-required.

### Fixed
- **Audit remediation (Fable 5 — High + Med/Low).** A batch of correctness and
  robustness fixes from an external audit pass:
  - Concurrency: synchronous in-flight guard on `/api/investigate`; `globalThis`-pinned
    scheduler + health module state so Next.js standalone doesn't re-init them per
    module graph; SSE `signal`/close cleanup on `/api/host-groups` and
    `/api/vulnerabilities/adversary-exposure`.
  - Approvals: fixed the multi-tab Approve button brick.
  - Sidecar: `_check_response` guard on host-group membership reads; fixed
    empty-catalog cache poisoning in `falcon_scripts`; char-class-aware zero-width
    assertion check in `exclusions.py`.
  - Agent loop: correct `max_tokens` handling; IR run-analysis truncated-JSON
    miscount.
  - Scheduler: `/api/scheduled/*` added to middleware public prefixes (it carries no
    session cookie and enforces its own `SCHEDULER_TOKEN`); the session redirect had
    made it permanently unreachable.
  - Deploy contract: added 9 sidecar tools to `expected_tools.json` (now 94);
    `/validate-bundle` polls the public `/api/healthz` instead of the authed
    `/api/health` (which would 302 and false-pass).
  - Long primers (>1500 chars) are stashed in `sessionStorage` via `buildPrimerHref`
    across all 10 launch sites, avoiding HTTP 431; added `describePrimer` matchers
    for the two Shadow-AI hand-offs so they render plain-English confirmation cards.
  - Cleanups: consolidated `DEFAULT_FALCON_BASE_URL`; `patching/rtr.py` reuses the
    shared FalconPy kwargs; `package.json` declares `engines.node >= 22`; pruned
    stale perf-logging references from docs.

## 0.6.4 — Falcon Discover surface + live scope-posture probe

### Added
- **`/discover` — Falcon Discover asset / application / account inventory.** A new
  read-only decision-doc surface following the staged-build pattern, but
  **sidecar-backed**: `falcon-mcp` 0.11.0 ships only `falcon_search_applications`
  + `falcon_search_unmanaged_assets`, so Accounts and managed-asset inventory come
  from new FalconPy-backed sidecar tools (`extras_discover_assets` /
  `_applications` / `_accounts` in `falcon-extras/discover.py`). The deterministic
  layer (`lib/discover/inventory.ts`) computes a posture summary — managed vs
  unmanaged coverage gaps, platform spread, privileged / local-admin accounts and
  password hygiene, applications flagged suspicious — and the agentic layer writes
  a verdict / context / recommended-actions document over the tenant totals. Nav
  item lives in the Posture group; gated on the new
  `FalconExtrasCapabilities.discover` flag and ships staged-build (hides + shows a
  scope-pending banner when the asset-inventory scope is absent). Verified
  end-to-end against a live tenant (10 assets, 1951 applications, 20 accounts).
- **`scripts/falcon-scope-probe.mjs` — live API-posture probe.** Decrypts each
  environment's stored Falcon credentials from `data/eyas.db`, mints an OAuth
  token, and classifies every documented scope by hitting a representative read
  endpoint (403 = denied, 200 = granted). This is the authoritative reconciliation
  for `components/ScopeChecklist.tsx` drift — OAuth tokens are opaque, so endpoint
  probing is the only way to know granted scopes. `node scripts/falcon-scope-probe.mjs --all`.

### Changed
- **`/status` operations add-on tool list is grouped, collapsible, and described.**
  The flat alphabetical list (which mislabeled every tool "write · approval-gated")
  is now bucketed into collapsible sections by security domain — Incident response,
  Containment, Identity protection, Shadow AI, Patching & remediation, Tuning &
  exclusions, Host groups, Policy & lifecycle, Data protection, Threat intel,
  NGSIEM, Asset discovery, Fusion SOAR workflows — each tool showing a brief
  description and an accurate `read` vs `approval-gated` badge. Descriptions are
  sourced live from the sidecar (new `toolDescriptions` field on the health
  report), so they track the tool docstrings and never drift; the domain
  classifier falls unknown tools into "Other" so new capabilities stay visible.
- **Operator-facing copy.** Chat activity status now reads "Eyas is thinking…"
  (was "Claude is thinking…") and "Connecting to Falcon…" (was "Connecting to
  falcon-mcp…", which leaked a framework name into user-facing copy).

### Fixed
- **Scope documentation reconciled against a live tenant probe.** Corrected
  console scope labels (Scheduled Reports is read-only; "NGSIEM Correlation Rules"
  → "Correlation Rules"; "Falcon Adversary Intelligence Recon" → "Monitoring Rules
  (Falcon Intelligence Recon)"; removed the non-existent "Discover" label and
  re-added the inventory scope under "Assets").
- **Data Protection read IS granted** (both probed tenants) — an earlier reading
  that it was denied came from a stale `data-protection/queries/classifications/v1`
  probe path; the real query endpoint is `v2`. `/data-protection` runs live
  (confirmed via `/api/health` capability map). The scope-probe path is fixed, and
  probes for Cloud Security Detections, Falcon Container Image, and Falcon Shield
  (SaaS Security) were added.
- **Scope posture is per-tenant.** The `CLAUDE.md` Falcon-scope section now frames
  grants as per-environment (gate against actually-granted scopes, never a
  hardcoded baseline) and documents the variance between the two probed tenants.
- **Tenant base URL must match its cloud region.** A region mismatch (e.g. a us-2
  tenant stored with the us-1 default) mints a valid OAuth token but 401s every
  API call; the `X-Cs-Region` header on the token response is the authoritative
  tell. Surfaced as an onboarding gotcha.

## 0.6.3 — Knowledge-base PDF fix (standalone)

### Fixed
- **PDF ingestion into the knowledge base now works in the standalone bundle.**
  `pdf-parse` bundles pdfjs, which on Node pulls `DOMMatrix` (and the
  rendering-only canvas path) from the optional native package
  `@napi-rs/canvas`. We deliberately don't ship that native binding (it would
  break the cross-platform bundle), and Node has no global `DOMMatrix` — so the
  first PDF upload threw `ReferenceError: DOMMatrix is not defined` and the
  ingest failed. The standalone server now installs a small pure-JS `DOMMatrix`
  before loading the parser (only when the runtime lacks one), so headless text
  extraction works. Text-only extraction never touches the canvas/image
  rendering path. A second gap was that pdfjs resolves its worker
  (`pdf.worker.mjs`) by a runtime path string the Next.js tracer can't follow, so
  the worker was missing from the bundle and parsing failed with "Setting up fake
  worker failed" — it's now opted into the standalone output. Verified end-to-end
  against the actual shipped bundle (canvas absent, worker present), including
  transformed multi-line text. Plain-text, Markdown, and Word ingestion were
  unaffected.
- **Silenced the benign pdfjs startup noise.** With the canvas package absent,
  pdfjs logged `Cannot load "@napi-rs/canvas"` plus `Cannot polyfill
  DOMMatrix/ImageData/Path2D, rendering may be broken`. These referred only to
  the unused rendering path; they're now filtered so they don't alarm operators.

## 0.6.2 — Documentation accuracy pass (SE release)

Buttoned-up cut for distribution to Sales Engineers. No runtime behavior change
beyond one dead-UI-hint removal; the bulk of this release is making every
shipped doc accurate against the current code.

### Docs
- **Audited and corrected every operator- and SE-facing doc against 0.6.x
  reality.** Fixed stale version stamps (README still said v0.3.0), the
  `Project Eyas` → `Eyas` rebrand that never propagated past the UI, the chat
  surface description (three starter prompts, not a fictional six; no
  "Playbooks" popover), and developer jargon that had leaked into operator copy
  (`FalconPy`, "sidecar", source file paths) in `USERGUIDE.md`.
- **`DEPLOYMENT.md` backup section rewritten.** It documented `auth.json` /
  `settings.json` backup targets that no longer exist — everything durable is
  in `data/eyas.db`. Added the backup-hygiene warning (a backup capturing both
  `data/` and `.env` defeats the at-rest encryption) and corrected the false
  "chat sessions don't survive restart" claim.
- **`SECURITY.md` brought current with the 0.6.0 hardening.** Documented the
  build-time deployment lock (read-seam enforcement), the `/register`
  SSRF / credential-exfil hardening, configuration-integrity atomicity, and the
  optional CrowdStrike AIDR guardrail.
- **Pruned previous-release archaeology from the shipped docs** so SEs see one
  coherent current product (the `0.3.0` baseline / `0.20.x` upgrade-path notes,
  per-release change tags, and stale `falcon-mcp` point-release numbers).
  Release history stays in `CHANGELOG.md`.

### UI
- Removed a dead `⌘K for palette` hint from the sidebar footer — the command
  palette was removed in 0.3.0 and no handler was ever wired.

## 0.6.1 — UI polish

### UI tweaks
- Chat input placeholder is now `Eyas…` (was `Computer…`).
- The conversations rail groups by relative day (Today / Yesterday / Earlier)
  and shows a filter box once there are more than six — much easier to scan a
  long history.
- Chat history idle TTL lowered from 7 days to **72 hours** (`TTL_MS`).
- Status page: the FalconPy add-on is renamed from "Host containment add-on" to
  **"Falcon operations add-on"** (it now covers IR, patching, host-group
  provisioning, and more — not just containment).
- Status page → API scopes: each scope row now shows a per-environment
  availability blip — green (granted), red (not granted), or grey (core /
  baseline scope, not probed) — with a legend naming the active environment.

## 0.6.0 — Security & reliability hardening

### Audit hardening pass — security-posture follow-ups
- **Fixed unauthenticated SSRF + credential exfiltration on `/register`.** The
  `testConnectionAction` server action (reachable unauthenticated, since
  middleware lets `/register` through) fetched an attacker-supplied Falcon Base
  URL with no validation and no timeout, and fell back to STORED credentials
  for any blank field — so a post-setup attacker could blank a field and have
  the server POST the stored Falcon client secret (and, via the Anthropic
  path, the stored token) to an attacker-chosen host, or SSRF internal
  endpoints (e.g. `169.254.169.254`). Now: the action requires an authenticated
  session once the app is registered (first-run setup is unaffected — no creds
  exist yet to leak); the Falcon Base URL is allowlisted against
  `FALCON_BASE_URL_RE` before any cred leaves the process; the probe reuses
  `probeFalconCredentials` (10s timeout); and on gateway-locked builds the
  Anthropic probe is forced to the baked gateway URL. Found by the 2026-06-08
  re-audit (`docs/audit-2026-06-08.md`, the sole High with an unauthenticated
  surface).
- **Fixed two silent data-loss bugs (audit HIGH — "state advanced before the
  work it represents is confirmed").** (1) The upstream-release watcher
  persisted the new tag BEFORE delivering the webhook, so a single transient
  delivery failure (Discord 429/5xx/network) advanced `last_tag` and the next
  run skipped — dropping that release notification forever. It now delivers
  first and persists only on confirmed-ok delivery (the first-run silent-init
  still writes without delivering). (2) A cancelled/disconnected chat turn
  skipped `saveConversation` but still wrote the IR audit turn, so executed
  writes/containment vanished from the resumable transcript while persisting to
  `ir_run_turns` — a resume then replayed a stale message list against
  already-moved Falcon state. The transcript is now persisted on cancel too
  (the agent loop guarantees `finalMessages` never ends on a dangling
  `tool_use`, so a partial turn resumes cleanly); only an AIDR-blocked OUTPUT
  still skips the save. As a side effect the `session_state` TTL emit is now
  gated on the actual save, so a non-persisted turn no longer over-promises the
  header TTL pill.
- **Gateway build-lock now enforced at the read seam.** `getAnthropicClient`
  applies the deployment policy where the client is actually constructed, not
  just at the `/config` save path: on a `gatewayOnly` (locked standalone)
  build it drops any stored API key and forces the baked `forcedGatewayUrl`,
  so a hand-edited DB row can no longer repoint a leaked bundle at a personal
  Anthropic account. Mirrors `validateAnthropicAgainstPolicy`.
- **`mutateSettings` is now genuinely atomic.** The settings write and the
  tamper-evidence audit-row append commit as ONE transaction (nested
  `rawDb().transaction()` → savepoint), and the in-memory cache only advances
  after the combined commit — closing the window where a failed audit append
  could leave a persisted settings change with no audit row plus a stale cache.
- **`/cost-summary` reads the live `cost_log` SQLite table** instead of a dead
  `data/cost-log.jsonl` (cost moved to SQLite), restoring the 68%-baseline /
  cache-hit QA check.
- **Settings test rewritten as a DB-backed store smoke test.** The old
  `test:settings-migration` harness exercised the pre-0.3.0 JSON-file
  migration and died on `no such table: settings` against the squashed
  schema. Renamed to `test:settings-store` and rewritten to cover the
  invariants the DB-backed store actually has — fresh-boot env synthesis,
  `mutateSettings` round-trip + audit row, the 0600 file mode, and a
  permanent regression test for the atomicity fix above (forces the audit
  INSERT to fail and asserts the settings write rolls back).
- **Shadow-AI prevention probes are now platform-aware.**
  `extras_shadow_ai_prevention_status` and
  `extras_shadow_ai_check_prevention_binding` previously matched only the
  Windows rule group, so a correctly-bound macOS or Linux prevention policy
  reported as broken. Each attached policy is now checked against ITS OWN
  platform's rule group (Falcon rejects cross-platform binds); status reports
  every platform in `platforms[]`, binding reports per-platform rule-group
  state + platform-tagged remediation steps, and readiness is computed across
  platforms. Top-level Windows-shaped keys preserved for the setup/audit UI.
  New `test:sidecar` suite `test_prevention_binding.py` (22 checks) guards it.
- **Reliability nits (audit #6).** Silent truncation now carries a signal:
  `/api/detections/tuning` and `/api/hosts/groups/members` return `truncated`
  (surfaced as "sampled (capped)" / "first N hosts" notes in the UI), and the
  patch host-enumeration endpoint reports `filter_degraded` + `unverified_count`
  when the sensor-managed cross-check faults (it still over-includes rather than
  drop hosts, but the verify card now warns some may be sensorless). Discord
  webhook delivery honors `retry_after` on 429 with a bounded retry instead of
  failing the whole briefing. The recurring-job runtime guards `cfg.run()` so a
  manual `fireNow()` can't overlap a scheduled fire (returns `skipped`). The DB
  shutdown checkpoint resolves the live handle dynamically, so a `closeDb()` +
  reopen is still flushed on exit. Knowledge-base FTS retrieval applies a
  corpus-relative relevance floor (drops the weak long tail so an incidental
  single-token match isn't injected as authoritative context).
- **Standalone packaging gaps closed.** (1) `start.sh` required Node ≥20 but
  the bundle ships better-sqlite3 prebuilds only for Node 22 (ABI 127) / 24
  (ABI 137) — a Node 20 user passed the gate then hit a cryptic native-binding
  failure; the floor is now Node 22 with a clear message, kept in sync with
  `BSQLITE_ABIS`. (2) `make-dist.sh` staged only `darwin-arm64` prebuilds, so
  Intel Macs ENOEXEC'd at launch; it now stages both `darwin-arm64` and
  `darwin-x64` across every supported ABI. (3) `/validate-bundle` now asserts
  the gateway deployment lock is actually baked — `build-info.json` carries
  `deploymentLock`, and validation greps the compiled `.next/` for the forced
  gateway URL so a build that shipped without the `build-flags` bake can't pass.

### Audit medium-severity + UX fixes (2026-06-08 re-audit)
- **Patch hand-off humanizer no longer leaks raw AIDs on truncated fleets**
  (audit HIGH #4). When a patch bundle exceeded the embedded-id cap the primer
  read "… on 25 (truncated from 40) hosts", which the matcher rejected, so the
  confirmation card rendered the raw `["aid1",…]` array + tool jargon. The
  matcher now absorbs the truncation clause. Added a "Triage hash" matcher too
  (it previously fell through to raw text, exposing the sha256 + composite_id).
- **Per-session chat lock.** Two concurrent turns on the same `sessionId`
  (double-submit / two-tab resume) clobbered each other's `saveConversation`
  (last-writer-wins) and drifted the IR turn count. The chat route now refuses
  the second with 409 (mirrors the env-switch refusal), released when the
  stream settles.
- **AIDR base URL allowlisted.** A PATCH to an environment persisted
  `aidr_base_url` unvalidated, and the AIDR bearer rides there every chat turn
  — now allowlisted to CrowdStrike / Pangea hosts (`AIDR_BASE_URL_RE`).
- **`/cost` no longer reads the whole `cost_log` table into JS.** A shared
  `summarizeCost()` aggregates in SQLite (`GROUP BY day×surface×model` with
  `json_extract` sums) so only grouped rows + the 25 most-recent come back;
  the page and the (previously dead-code) `/api/cost` route share it.
- **Cache-write cost undercount fixed.** Pricing carried only the 5m-TTL write
  rate (1.25× input) while the loop caches the tool catalog + chat system
  prompt at 1h (2×); raised to 2× in `pricing.ts` and the duplicated
  `cost-summary` skill table.
- **Tool-result blobs parsed once.** `tool-bridge.invoke` parsed each raw
  Falcon payload twice (error check + projection); now parses once and passes
  the array through.
- **`/cases` no longer renders raw upstream errors to operators.** Raw 500
  bodies / FQL parse errors are logged server-side; the page shows a fixed
  plain-language message.
- **Tests:** new `parseConcatenatedJson` + `detectFalconError` suite
  (`test:parse`, 13 cases — the most load-bearing previously-untested function);
  added patch-truncated + triage-hash cases to `test:primer`.

### Audit hardening pass (reliability + correctness)
- **Critical IR fix:** the Phase 0 actionability gate no longer mis-classifies
  recent real malware as retrospective backfill. It previously compared each
  detection's underlying event timestamps against `now` — and since every real
  detection's events predate now, real malware was bucketed "retrospective" and
  FP-closed without containing the host. Phase 0 now keys off the **gap between
  the fresh `created_timestamp` and the old underlying events** (the true
  backfill signal); Phase 3 keeps its quarantine-point cutoff. Regression-guarded
  by new `test_backfill_*` cases.
- **Wrapped Falcon 500s surface as real errors** to the agent. `tool-bridge`
  now runs `detectFalconError` on the agent path, so an upstream 500 returns
  `isError: true` instead of an empty success + a "don't refetch" note that
  silently under-scoped IR Phase 0.
- **IR propagation wait survives the MCP timeout.** `extras_rtr_wait_until_ready`
  gets a per-call transport-timeout override so the 5-min Phase 1.5 wait isn't
  aborted at ~60s (which had forced the workflow to HOLD).
- **Approval gate releases on disconnect.** `awaitApproval` is now signal-aware:
  a tab-close / Stop during a pending write-approval resolves immediately instead
  of pinning the in-flight lock (env-switch 409s) + idle MCP clients for 5 min,
  and no longer leaves a resumable Allow button on a dead loop.
- **Docker now runs falcon-mcp 0.11.0** (was pinned to 0.9.0, which 404'd the
  /quarantine, /correlation, /data-protection, and /cases surfaces on every
  Docker deploy). Plus smaller fixes: OAuth/Falcon probe timeouts, host-search
  request aborts, threat-graph explicit-type validation, at-risk timestamp
  ordering, release-watcher atomic writes, Falcon-scripts cache no longer
  poisoned by a 403, sub-agent tool-call traces now show output, and several
  doc/dead-code cleanups.

### Chat hand-offs are human-readable
- Every action-button hand-off (IR, Triage, Reconstruct, Tune, Patch, Case, …)
  now opens chat as a **confirmation card** instead of dumping a wall of
  tool-name/id instruction text into the composer. The card shows a
  plain-English title + a "what this does / why" line, **Start / Cancel / Edit
  as message**, and a collapsible **Instructions** disclosure with the precise
  agent prompt. Nothing runs until Start; after Start the user bubble shows the
  summary with a "Show instructions" toggle.
- All operator-facing hand-off copy now lives in one place,
  `components/primer.ts::describePrimer` — a receiver-side humanizer that maps
  any instruction (button-emitted *or* the `[label](/?primer=…)` links the
  agent writes in responses) to clean copy. The precise instruction is
  **preserved, never rewritten**, so server-side IR detection and every agent
  contract are unchanged, and resumed conversations re-humanize for free.
  Pinned by `npm run test:primer` (every template + a jargon-leak guard).

### IR button is predictable everywhere
- One shared predicate (`lib/hosts/ir-eligibility.ts`) + a unified `IrChip`
  drive both `/hosts` and `/queue`. The chip is **always shown** in one of three
  explicit states: **live** (eligible), **greyed-with-reason** (non-Windows /
  RTR-disabled), or **greyed-linking-to-Config** (IR not configured for the
  environment) — answering "when should I expect to see IR?".
- **Bug fix:** `/queue` previously applied no platform check, so a Linux host
  could surface a live IR button. It now uses the same gate as `/hosts`.
  Pinned by `npm run test:ir-eligibility`.

### Same-turn host-group provisioning fix (high-stakes)
- The falcon-extras sidecar runs one process per chat turn with a frozen
  `os.environ`. A group created/adopted mid-turn was therefore invisible to a
  same-turn `diagnose`/`provision`/playbook call, which stale-read
  `no_group_id` even though the id had been saved — sending operators to paste
  ids into `/config` by hand. Fixed with a process-local override
  (`falcon_helpers.set_runtime_group_id` / `resolve_group_id`, precedence
  explicit > override > spawn-time env) wired through every consumer. The
  `create_*` next-step copy and the IR/Shadow-AI setup-card primers no longer
  tell operators to save the id manually. Pinned by
  `falcon-extras/test_group_id_resolution.py` (in `npm run test:sidecar`).

## 0.5.0 — Eyas rebrand + agentic Data Protection provisioning

### Rebrand: "Project Eyas" → "Eyas"
- "Project" dropped from all user-facing copy — wordmark, topbar lockup,
  login/register hero, page-title metadata, footer, chat export. The
  `Wordmark` component no longer renders a "PROJECT" tier; the topbar center
  lockup is "EYAS" in oxblood. Positioning is unchanged — Eyas remains the
  human-in-the-loop, approval-gated operator console, not unattended SOC
  autonomy. Canonical Falcon object names (`Project Eyas - IR Quarantine`,
  `Project Eyas - Shadow-AI Banned`) are deliberately preserved — they're
  tenant host-group lookup keys, not copy.

### Data Protection: read-only → agentic write chain
- falcon-mcp 0.11.0 ships Data Protection read-only; the create side now lives
  in the FalconPy sidecar (`falcon-extras/data_protection.py`,
  `DataProtectionConfiguration`). Three approval-gated write tools build the
  DLP chain bottom-up: **content pattern → classification → policy** —
  `extras_create_data_protection_content_pattern` / `_classification` /
  `_policy`. Bodies are constructed deterministically with monitor-first
  defaults (classification `protection_mode=monitor`, `block_all_data_access`
  off); the agent supplies ids + regexes, not the 40-key `policy_properties`.
- New agentic provisioning workflow: `/data-protection` gets a **"Provision
  coverage"** hand-off that seeds chat with a one-line primer pointing at
  `extras_data_protection_provision_playbook`. The agent prechecks existing
  coverage (no redundant patterns), synthesizes + validates the match regexes
  from the operator's plain-language description, then stands up the chain
  monitor-first — each write approved before it lands.
- Validated end-to-end against a live tenant (create chain + cleanup). Two
  Falcon field quirks handled: `region` must be `ALL` / ISO-3166 alpha-3 (not
  `global`); name/description fields reject em-dash/en-dash (auto-coerced to
  hyphen, same quirk as prevention policies).
- Scope: **Data Protection now requires write** — `ScopeChecklist`, CLAUDE.md
  scope section, and the sidecar deploy contract (`expected_tools.json`)
  updated in lockstep.

## 0.4.0 — Knowledge base + falcon-mcp 0.11.0 surfaces

### Per-environment knowledge base
- Operators attach reference documents (PDF / Word / Markdown / text) to a
  Falcon environment on `/config`. The chat agent retrieves relevant passages
  per turn and cites them. Storage is DB-backed (SQLite `knowledge_docs` +
  an FTS5 `knowledge_chunks` index, migration `0003`); retrieval is
  deterministic lexical search (no embeddings, no external vendor — works in
  standalone/gateway-only). Injected into the chat loop via a new uncached
  `contextBlocks` seam on `runAgentLoop`. First file-upload surface in the app.

### falcon-mcp 0.11.0 + FalconPy 1.6.2
- Upstream pins bumped (`versions.json`). Three new modules each get a full
  agentic decision-document surface, all staged-build (nav hides + scope-pending
  banner until the scope is granted):
  - **`/quarantine`** — deterministic host/hash clustering of quarantined files
    + agentic verdict; release / delete handed to chat (approval-gated).
  - **`/correlation`** — NGSIEM correlation-rule health (active/inactive,
    severity, MITRE coverage, staleness) + agentic assessment; tune / disable
    handed to chat (approval-gated).
  - **`/data-protection`** — data-exposure posture (policies, classifications,
    content patterns) tied to live `product:'data-protection'` detections.
    Read-only.
- The new upstream write tools (`falcon_update`/`delete_quarantined_files`,
  `falcon_create`/`update`/`delete_correlation_rule(s)`) are approval-gated.

### Security
- Bumped `drizzle-orm` to 0.45.2 (fixes a high-severity SQL-injection-via-
  identifiers advisory; the app uses only static identifiers, so it was not
  exploitable here). No high/critical npm advisories remain.

## 0.3.3 — Chat UX: fresh-on-return + better titles

Two small fixes to the chat-history surface shipped in 0.3.0:

- **`/chat` always opens on a fresh conversation.** Previously the page
  auto-resumed the last active session whenever the user navigated back
  to chat from elsewhere in the console. That implicitly mixed prior
  context into new questions and clobbered primer hand-offs that
  expected an empty turn list. Now the mount always mints a new
  session; prior conversations are still resumable from the left rail
  by explicit click.
- **Conversation rail shows the prompt, not a timestamp.** The rail
  now derives a title from the first user message even when the stored
  `title` column is null (covers chats created before the title
  feature, plus any that missed the set-once write). The
  `Chat — May 25, 18:32` placeholder is now a true fallback, not the
  default.

No DB migration, no config change.

## 0.3.2 — CrowdStrike AIDR guardrails for chat + DB durability fixes

### CrowdStrike AI Detection and Response (AIDR) integration

Optional per-environment guardrail layer for the chat surface. When the
AIDR API token is configured on an environment, every chat prompt is
scanned before reaching Anthropic, and every assistant response is
scanned before being saved to the transcript. Blocked turns surface as
a shield bubble identifying which detectors fired (prompt injection,
sensitive data, malicious URL/IP, secret/credential, off-policy topic,
etc.); blocked output is dropped from the conversation so it can't
leak into future-context resume.

- Per-environment credential (token + base URL) stored encrypted at
  rest alongside Falcon creds. New AIDR card on `/config` for the
  active environment with paste/disable controls.
- New `/api/health::probeAidr` probe — reports `disabled` when
  unconfigured, otherwise a real connectivity check against the
  CrowdStrike endpoint.
- Append-only `aidr_blocks` audit table records every block verdict
  with a sha256 preview hash (offending text itself is not stored).
- Fail-open on transport errors: a CrowdStrike edge blip surfaces as
  an amber banner on the turn rather than taking chat down.
- New migration `0002_aidr.sql`; uses `ALTER TABLE ADD COLUMN`, so
  fresh installs and 0.3.0 / 0.3.1 upgrades both pick it up without
  data loss.

### DB durability — shutdown WAL checkpoint

`lib/db/client.ts` now registers SIGTERM / SIGINT / SIGHUP /
`beforeExit` handlers that run `wal_checkpoint(TRUNCATE)` + `close()`
before exit. Previously every kill left writes only in `eyas.db-wal`
and the main `eyas.db` file stayed at the ~12 KB empty-schema size
indefinitely — any tool reading the main file alone (backups, sync
utilities, the migration runner's pre-fresh snapshot) got nothing,
and a misguided `rm eyas.db-wal` would wipe the operator's entire
config silently. SQLite's auto-checkpoint trigger (1000 pages, ~4 MB)
is well above what this app accumulates between releases, so the
explicit handler is the real durability story.

### Auto-save fix for chat-driven host group adoption

`AUTO_SAVE_TOOLS` in the chat route persists the host group ID that
`extras_create_*_host_group` and `extras_adopt_*_host_group` return.
The path silently no-op'd from v0.20.3 onward because
`extractCreatedGroupId` only handled the raw MCP `Array<{type,text}>`
content shape, while `tool-bridge.invoke` actually returns content as
a joined string. Operators using the chat-driven adopt flow had to
re-paste the ID into `/config` by hand. Fixed to accept both shapes.

## 0.3.1 — macOS first-launch fixes

Patch release. Fixes two separate macOS first-launch failures observed on
recipient Macs after `unzip → ./start.sh`. No application code changes.

### Gatekeeper quarantine

`start.sh` now detects `com.apple.quarantine` on the bundle root and strips
it recursively before launching `node server.js`. Idempotent — runs only
when the attribute is actually present, and no-ops on Linux.

macOS tags every file extracted from a Safari/Mail/Slack-downloaded zip with
`com.apple.quarantine`. Gatekeeper then refuses to load unsigned native
`.node` files with the "could not verify free of malware" dialog. We ship
the official upstream WiseLibs prebuild (SHA-256-verified byte-identical to
`github.com/WiseLibs/better-sqlite3` Releases), but without an Apple
Developer ID notarization the attribute must be removed locally.

### Multi-ABI better-sqlite3 selector

The bundle now ships one prebuild per supported Node ABI (currently 127 for
Node 22 LTS and 137 for Node 24) under
`vendor/better-sqlite3-prebuilds/<target>-<abi>/`. `start.sh` reads
`process.versions.modules` from the recipient's Node and copies the matching
prebuild over the path Next.js standalone expects.

Previously the bundle hard-coded a single ABI; recipients on a different
Node major hit "compiled against a different Node.js version using <N>" on
launch. The selector is offline-only (no network access at runtime), uses
the same trust chain as before (build-time fetch from upstream WiseLibs
Releases), and fails fast with a clear error if the recipient's Node ABI
isn't pre-staged. Add a new ABI by appending it to `BSQLITE_ABIS=(…)` in
`make-dist.sh` when a new Node LTS lands.

## 0.3.0 — Fresh-baseline production cut

Project Eyas re-versioned as 0.3.0 with a clean break from the prior
0.20.x line. No upgrade path from earlier versions; existing installs
should treat this as a new product.

### Production-readiness pass

The 0.3.0 release is the first cut focused on production-grade
operation rather than POC plumbing. Highlights:

- **Dead-code removal.** `FALCON_EXTRAS_ENABLED` toggle, the unused
  command-palette `⌘K` surface, and ~20 dead conditional branches across
  API routes have all been deleted. Sidecar is unconditionally on.
- **Schema reset.** Three legacy migrations squashed into a single
  `0001_init.sql` baseline. `falcon_extras_enabled` column removed.
  Fresh-install only — `data/eyas.db` is created from this schema and
  no in-app legacy import exists.
- **Hot-path parallelism.** `/api/vulnerabilities/hosts-for-patch` now
  shards its `falcon_search_hosts` fan-out across a 4-client pool
  instead of spawning one client per 100-device chunk (~50s saved on
  large CVE sets). `/api/shadow-ai/fleet` no longer pulls 5K hosts up
  front; egress-scan results drive a targeted enrichment query.
- **New `/detections` Triage column.** Per-row chip hands off to chat
  with a decision-doc primer mirroring the `/queue` Triage pattern.
- **Workflows failed-execution hand-off.** The Fusion SOAR posture
  report now renders failed-row Status cells as markdown links into a
  chat primer keyed on `execution_id`, so the operator can drill into
  root cause without leaving the page.
- **Cases triage prompt.** New section in the chat system prompt
  defines the five-section decision doc (Context · Evidence ·
  Cross-module enrichment · Verdict · Recommended actions) for the
  per-case Triage primer hand-off.
- **Shared API response envelope.** New `lib/api/respond.ts` exports
  `ok` / `fail` / `scopePending` / `serverError`. Sweep started in the
  representative routes (environments, queue/claim, cases, detections);
  other routes adopt as they are touched.
- **Sidecar observability.** New `swallow_exc(exc)` helper in
  `falcon_helpers.py` logs swallowed exceptions to stderr (inherited
  by the parent Next.js process) so production ops can correlate
  failures without losing the MCP-friendly response shape. Swept 70
  catch sites across 24 sidecar modules.
- **Operational log gating.** New `lib/log.ts::debugLog` gates routine
  scheduler / bootstrap info chatter behind `DEBUG_LOGS=true`. Errors
  remain on `console.error` always.
- **Type-cleanup.** Removed unsafe `as unknown[]` casts in
  `lib/mcp/projections.ts` and `app/api/cases/route.ts` in favor of
  `Array.isArray` narrowing.

### Breaking

- Anyone with a v0.20.x install must start over: delete `data/eyas.db`
  and any `data/*.json` artifacts, boot 0.3.0, and re-register through
  `/register`. The `scripts/import-from-v020.mjs` importer has been
  removed.
- `FALCON_EXTRAS_ENABLED` environment variable is no longer read.
- `falcon-extras` sidecar is always on; the `falconExtras` toggle is
  gone from the settings file and the SQLite schema.
