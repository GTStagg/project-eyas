---
name: audit-write-tools
description: Use to verify every write-shaped Eyas tool is approval-gated and that no caller bypasses the registry. Diffs the `lib/eyas-tools/` tool names against `lib/mcp/write-tools.ts::REQUIRES_APPROVAL`, and lints `runAgentLoop` callsites for `requiresApproval: () => false` overrides. Run after adding any new Eyas tool or any new `runAgentLoop` callsite. Trigger phrases: "audit write tools", "check approval gates", "are the writes gated", "any approval bypasses".
---

# audit-write-tools

Failure modes this catches:

1. **A new Eyas tool that mutates Falcon state ships without a registry entry.** The agent loop only pauses for tools in `REQUIRES_APPROVAL`. A new `extras_create_*` / `extras_delete_*` / `extras_run_*` tool that someone forgot to register is silently un-gated — the agent can call it from chat and the operator never sees the approval dialog.

2. **A `runAgentLoop` callsite passes `requiresApproval: () => false`.** That custom function REPLACES the registry check entirely (see `feedback_never_disable_approvals`). Copying this from a read-only route into a write-capable surface neutralizes every gate at once. The IR route had this bug 2026-05-02 and ran a `host-delete-folder` without approval.

3. **A native write becomes reachable ungated, or an adopted one loses its gate.** Native writes split into two categories:
   - **SUPPRESSED** (`NATIVE_WRITES` in `run.sh`) — Eyas has its own tool with a check that runs before the write (zero-width pre-flight, canonical naming + auto-save, dynamic-group refusal, disable-before-delete, monitor-first defaults; `falcon_set_policy_precedence` is fleet-wide with no Eyas tool). Hidden at the bridge (`NATIVE_WRITE_SUPPRESS` in `lib/mcp/tool-bridge.ts`) AND listed in `REQUIRES_APPROVAL` as a fail-closed backstop. Invariant: in BOTH sets.
   - **ADOPTED** (`NATIVE_ADOPTED` in `run.sh`, e.g. `falcon_update_detections`, `falcon_execute_workflow`, `falcon_delete_exclusions`, `falcon_update_policy`, `falcon_contain_hosts`) — native is the agent's primary write path: exposed (NOT suppressed) AND gated. Invariant: gated AND NOT suppressed.

   The skill enforces both invariants, asserts the two lists are disjoint, and flags drift in either direction.

4. **The annotation approval backstop wiring is removed.** falcon-mcp 0.13.0 sets MCP tool annotations comprehensively (`readOnlyHint:false` on every write). The bridge collects VISIBLE native writes into `annotatedNativeWrites` and the agent loop gates on `requiresApproval(name) || annotatedNativeWrites.has(name)` — so a native write added in a future falcon-mcp bump but not yet in `REQUIRES_APPROVAL` still gates **fail-closed** (and logs an `APPROVAL DRIFT` line) instead of firing ungated. The skill structurally verifies this wiring is present in `tool-bridge.ts` + `agent-loop.ts`. The **live** drift list (which native writes are annotated-but-ungated on the configured version) is computed by the catalog and surfaced on `/agent-toolbox` as `driftWarnings` — that's the automated "did a bump add a write we forgot to gate?" signal; this skill only checks the mechanism exists.

## Run

```bash
bash .claude/skills/audit-write-tools/run.sh
```

Exits 0 if all gates accounted for, non-zero otherwise. Output format:

```
[1mWrite-shape sidecar tools[0m
  ✓ extras_host_group_add_members (gated)
  ✓ extras_host_group_remove_members (gated)
  …
  ✗ extras_new_thing (UNGATED — add to REQUIRES_APPROVAL)

[1mrunAgentLoop callsites[0m
  ✓ app/api/queue/route.ts (no override)
  ✗ app/api/foo/route.ts:55 (passes `requiresApproval: () => false` — BYPASS)

PASS · 14 gated / 14 candidates · 0 bypasses
```

## What counts as "write-shaped"

Sidecar function names matching:

- `extras_(create|delete|update|add|remove)_*`
- `extras_*_(contain|containment|execute|run_patch|run_cleanup|run|launch)`
- `extras_*_(group|members)_(add|remove|set)`

Falcon-mcp upstream tools: hard-coded list (mirrors the registry's upstream entries — `falcon_add_ioc`, `falcon_create_*`, `falcon_delete_*`, `falcon_update_*`, `falcon_launch_*`).

Read-only tools that match the regex but are intentionally un-gated (allowlist):

- `extras_rtr_check_patch_status` — polls existing in-flight cloud_request_ids; no new invocation.

Anything matching the regex but not in the allowlist must appear in `REQUIRES_APPROVAL`.

## What's checked at callsites

Every file under `app/` and `lib/` that imports `runAgentLoop` from `@/lib/chat/agent-loop`. The skill greps each callsite for an explicit `requiresApproval:` property and flags it. Comments referencing the property are tolerated; only actual property assignments fail.

The default (omitting the prop entirely) is correct — the loop falls through to the registry check.

## Fail handling

| Failure | Fix |
|---|---|
| Sidecar tool ungated | Add the tool name to `REQUIRES_APPROVAL` in `lib/mcp/write-tools.ts` |
| Allowlist drift (a tool in the allowlist that no longer exists) | Remove the stale entry from `run.sh::ALLOWLIST` |
| Callsite override | Delete the `requiresApproval` line; let the registry default fire |
| Suppressed native (`NATIVE_WRITES`) not gated | Add it to `REQUIRES_APPROVAL` (the fail-closed backstop) |
| Suppressed native (`NATIVE_WRITES`) not actually suppressed | Add it to `NATIVE_WRITE_SUPPRESS` in `lib/mcp/tool-bridge.ts` — or, if you mean to adopt it, move it to `NATIVE_ADOPTED` in `run.sh` and remove its twin |
| Adopted native (`NATIVE_ADOPTED`) still suppressed | Remove it from `NATIVE_WRITE_SUPPRESS` — an adopted native must be visible to the agent |
| Adopted native (`NATIVE_ADOPTED`) not gated | Add it to `REQUIRES_APPROVAL` (adopted natives are exposed-and-gated, like upstream writes) |
| A native name in BOTH lists | Lists must be disjoint — classify the write as either suppressed or adopted, not both |
| Suppress-set name not in audit's `NATIVE_WRITES` | A 0.12.x bump added/renamed a native write — re-dump `list_tools()` and classify it into `NATIVE_WRITES` or `NATIVE_ADOPTED` in `run.sh` (and update both code sets) |
| Annotation backstop wiring missing | Restore `annotatedNativeWrites` in `lib/mcp/tool-bridge.ts` (built from `t.annotations?.readOnlyHint === false`) and the union gate in `lib/chat/agent-loop.ts` |
| `/agent-toolbox` shows `driftWarnings` | A native write is annotated writable but not gated — add its name to `REQUIRES_APPROVAL` in `lib/mcp/write-tools.ts` (the loop already gates it via the backstop, but the registry should be authoritative) |
