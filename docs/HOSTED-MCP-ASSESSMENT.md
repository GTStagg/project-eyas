# Hosted CrowdStrike MCP vs. self-hosted eyas-mcp — assessment

**Date:** 2026-11-07 · **Context:** upstream `falcon-mcp` entered maintenance mode in 0.20.1 (2026-11-03). Eyas continues the server as an independent project (**eyas-mcp**) and, separately, build a second variant of the console against CrowdStrike's hosted gateway at `https://mcp.crowdstrike.com`. This document records what we verified about the gateway, what that means for Eyas's architecture, and a recommended shape for the two-build split.

Everything under "Verified" was observed live on 2026-11-07 (read-only: OAuth discovery, `initialize`, `tools/list`, one `search_tools` call; **no tool was executed**). Anything else is marked as inference or upstream documentation.

---

## 1. What upstream said (0.20.1, #591)

- New features ship only in CrowdStrike MCP; `falcon-mcp` gets security and dependency fixes only. No feature requests or feature PRs accepted. An end-of-life date will be announced before the repo is archived.
- CrowdStrike MCP is available in **US-1, US-2, EU-1** only.
- "Most tools keep the same `falcon_*` names." Tool access follows Falcon roles/permissions; activity is recorded in the **Falcon audit log**.
- Documented self-hosted-only surfaces: **Fusion SOAR**, **Zero Trust Assessment**, `falcon_search_guardian_prompts`, `falcon_search_managed_assets`. The hosted server splits the unified `policy_type` policy tools into per-type variants (`falcon_search_policies_prevention`, `_firewall`, …).

## 2. What we verified about the gateway

| Aspect | Finding |
|---|---|
| Endpoint | `https://mcp.crowdstrike.com/v1`, Streamable HTTP. Server identifies as `agentgateway-mcp-server` 1.0.0. |
| Auth | RFC 9728 protected-resource metadata → authorization server `https://api.crowdstrike.com` (Falcon's own OAuth2). Bearer token in `Authorization` header. Grants: **`client_credentials`** and `authorization_code` + PKCE (S256). |
| Credentials | **A token minted from an existing Falcon API client (`client_credentials`) is accepted.** The same API client Eyas already stores per environment works — no new credential type is needed for a server-side build. |
| Tool surface (`tools/list`) | **Two tools only:** `search_tools` (annotated `readOnlyHint:true`) and `execute_tool(name, arguments)` (**no annotations**). |
| Catalog (`search_tools`) | Structured result, ~318 KB unfiltered. Per tool: `name`, `module`, `description`, `annotations: {read_only, destructive}`, full `input_schema`, and for some tools an `output_schema`. For our US-1 test API client: **134 tools — 95 read-only, 39 writes (10 destructive)**, plus a `modules` list. |
| Delta vs. self-hosted (same credential) | **Hosted-only (16):** per-type policy tools (`*_policy_prevention`, `*_policy_firewall`, …), `falcon_get_compliance_posture`, `falcon_get_data_security_entity_schema`. **Not visible on hosted (52)** with this credential: all RTR, exclusions, AgentWorks, Fusion SOAR, ZTA, cloud insights/risks/groups, CSPM suppression, `falcon_idp_investigate_entity`, `falcon_search_guardian_prompts`, `falcon_search_managed_assets`, unified policy tools. |

**Caveat on the "not visible" list.** The `modules` list advertises `rtr`, `exclusions`, `idp`, and `agentworks`, but no tools from those modules came back, and upstream says RTR and cloud insights *are* on the hosted server. The likely explanation is that the catalog is filtered by the calling credential's scopes/roles. Re-run the probe with a broadly scoped API client before treating any gap as permanent. Only the four tools upstream documents as self-hosted-only should be treated as hard gaps.

## 3. What this means for Eyas's architecture

The defining choice in Eyas is the in-process MCP client with a manual tool-use loop, picked for **data residency, network exposure, per-tool approval gating, and ownable audit logging**. Against the gateway:

1. **Per-tool approval gating survives, but moves one level down.** The model would see only `execute_tool`, so gating keyed on the outer tool name gates either everything or nothing. The gate has to key on `execute_tool`'s **inner `name` argument**. The registry (`REQUIRES_APPROVAL`) and the annotation backstop both carry over, because `search_tools` supplies `read_only`/`destructive` per inner tool. The current backstop would *not* catch `execute_tool` on its own: it has no annotations, so a naive port fails open. **This is the single most important thing to get right in a hosted build.**
2. **Don't hand the model the discovery pattern.** Eyas biases the agent toward known `falcon_*` names and relies on bridge suppression to route writes to sidecar twins. Exposing `search_tools`/`execute_tool` directly would bypass both: the agent could discover and call a suppressed native write (e.g. `falcon_create_host_group`) instead of its twin. **Recommended:** the bridge calls `search_tools` once per session (cacheable, it's the 318 KB catalog), synthesizes ordinary per-tool definitions from `input_schema`, applies the existing suppression and filter sets, and translates each call into `execute_tool(name, arguments)`. The agent loop, projections, approval gate and UI then stay unchanged. This is the main build item for the hosted track.
3. **Data residency and network exposure invert.** Falcon data flows from the gateway to Eyas over the public internet rather than from a private-bridge child process. Data never reaches a third party beyond CrowdStrike and Anthropic, so the change in exposure is modest, but the "falcon-mcp stays on a private bridge" property no longer holds.
4. **Audit logging gets better.** Calls land in the Falcon audit log, in addition to Eyas's own `ir_runs` / `cost_log` / `settings_audit`. Worth surfacing as a selling point of the hosted build.
5. **The sidecar stays.** Everything `falcon-extras/` does (IR workflow, RTR patching, FalconPy-only surfaces, monitor-first DLP creates, canonical-named provisioning) is independent of which MCP server serves the native tools. Both builds keep the sidecar.
6. **Region coverage.** US-1/US-2/EU-1 only. Tenants on US-GOV or EU-2 etc. must use the eyas-mcp build. The hosted build should refuse (or fall back) per environment based on `falcon_base_url`.
7. **Tool-name drift is real but bounded.** The policy split is the main rename. Eyas's route code calls `falcon_search_policies` / `falcon_search_policy_members` / `falcon_update_policy` etc. directly in places, so those callsites need an alias layer: a small name map in the bridge, not per-route forks.
8. **Response shape: unverified.** We did not execute a tool, so we haven't confirmed whether `execute_tool` returns the same `{results, pagination}` envelope and `isError:false` error convention that `lib/mcp/parse.ts` is built around. The presence of `output_schema` suggests structured content may be returned for some tools. Probe this first: it decides whether dashboards work unmodified.

## 4. Recommended shape for the two builds

**One codebase, a transport/provider seam, two build flavors** — not two forks. The split is narrow:

| Layer | eyas-mcp build (current) | Hosted build |
|---|---|---|
| `lib/mcp/falcon-client.ts` | stdio spawn of eyas-mcp (pinned in `versions.json`) | Streamable HTTP to `mcp.crowdstrike.com/v1`, bearer token minted via `client_credentials` from the active environment's stored API client (refresh on expiry) |
| `lib/mcp/tool-bridge.ts` | `listTools()` → filter/suppress | `search_tools` → synthesize per-tool defs → same filter/suppress → calls translated to `execute_tool` |
| Name aliases | none | small map (unified policy tools ↔ `*_prevention` / `*_firewall`) |
| Approval gate / projections / routes / UI | unchanged | unchanged (gate keys on synthesized inner names) |
| Capability gating | `lib/health.ts` probes | same probes; absent tools (credential-filtered) degrade surfaces through the existing scope-pending path |
| Sidecar | yes | yes |
| Region | any | US-1 / US-2 / EU-1; per-env guard |

Select the flavor with a build-time flag alongside `BUILD_FLAGS` in `lib/config/build-flags.ts` (`make-dist.sh` already bakes flags per bundle). Optionally also allow a per-environment runtime choice later.

**eyas-mcp track (self-hosted) — near-term to-dos:**
- ✅ Done (v0.9.1): `versions.json` now pins `mcp-server-*` (package `eyas-mcp`, `https://github.com/GTStagg/eyas-mcp.git` @ a commit); dev spawn, `make-dist.sh`, `start.sh` and `/status` all read the package name from there — so a future hosted build swaps the provider without touching routes.
- The gaps Eyas works around become eyas-mcp's backlog. Candidates that would let Eyas delete workarounds: clamp Data Security search `limit` to 200 (or chunk the hydrate); monitor-first defaults on `create_data_security_entity`; port `offload_to_thread` concurrency to remain shared-client safe; structured content on search results.
- ✅ Done (2026-11, through eyas-mcp 0.21.0): most of the sidecar's generic gap-fillers moved into eyas-mcp — Discover (all asset types), Recon, Workflows listings, bounded NGSIEM search with a CQL check, verified host-group membership, prevention posture, RTR custom-script upload / run / status / delete, a runscript readiness probe, and bulk detection close (including single-host NGSIEM alerts). Eyas keeps its content (script library, playbooks, classifier, provisioning) and runs it on those natives.
- Security and dependency fixes from upstream are eyas-mcp's job (it reviews upstream diffs); Eyas only moves its pin.

**Hosted track — suggested order:**
1. Execute-path probe (read-only tools only): confirm the `execute_tool` result envelope + error convention against `lib/mcp/parse.ts`.
2. Re-run the catalog probe with a broadly scoped API client to separate credential filtering from true gaps.
3. Build the bridge synthesis + `execute_tool` translation + inner-name approval gating, with an `/audit-write-tools` invariant that `execute_tool` is never exposed raw.
4. Name-alias map for the policy split; run the dashboards.
5. Decide UX for self-hosted-only surfaces on the hosted build (Fusion SOAR, ZTA, prompt inspection, managed assets): hide via capability gate, or back them with sidecar FalconPy equivalents.

## 5. Open questions

- Does the gateway enforce per-tool authorization beyond OAuth scopes (Falcon RBAC roles on an API client)? That governs whether the catalog differs between `client_credentials` and a user's `authorization_code` token.
- Token lifetime / rate limits on the gateway vs. the direct API.
- Whether `output_schema` tools return `structuredContent`, and whether that's stable enough to replace our text parsing.
- Licensing/SKU: is the hosted server available to every Falcon tenant, or gated by a subscription?
