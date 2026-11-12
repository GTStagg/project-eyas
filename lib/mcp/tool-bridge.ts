import "server-only";
import type Anthropic from "@anthropic-ai/sdk";
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { projectToolResult } from "./projections";
import { detectFalconError, parseToolResultObjects } from "./parse";
import { EXTRAS_READ_ONLY, REQUIRES_APPROVAL } from "./write-tools";
import type { CallNative } from "./native-dispatch";
import { canonicalResources, canonicalTools } from "@/lib/llm/prompt-cache";
import { EYAS_TOOLS, EYAS_TOOL_MAP } from "@/lib/eyas-tools";
import type { EyasToolContext, NativeSearchResult } from "@/lib/eyas-tools/types";
import { shapeNativePayload } from "./native-shape";

export type FalconResource = {
  uri: string;
  name?: string;
  description?: string;
};

export type ToolBridge = {
  anthropicTools: Anthropic.Tool[];
  resources: FalconResource[];
  /**
   * VISIBLE native (falcon-mcp) tools that advertise a write via MCP tool
   * annotations (readOnlyHint:false). The agent loop gates on
   * requiresApproval(name) OR membership here — a fail-closed backstop so a
   * native write added in a future falcon-mcp version, but not yet added to
   * REQUIRES_APPROVAL, is still approval-gated (and logged as drift) instead of
   * firing ungated. The explicit REQUIRES_APPROVAL list stays authoritative;
   * this is defense-in-depth, and gating MORE on a hint is always safe.
   */
  annotatedNativeWrites: ReadonlySet<string>;
  /**
   * Visible falcon-extras tools that are neither approval-gated nor on the
   * reviewed read-only list (EXTRAS_READ_ONLY). The sidecar carries no
   * annotations, so an unclassified tool is assumed to write: the agent loop
   * gates it (logging drift) and sub-agents never see it.
   */
  unclassifiedSidecarTools: ReadonlySet<string>;
  invoke: (
    name: string,
    input: Record<string, unknown>,
  ) => Promise<{ content: string; isError: boolean }>;
};

const READ_RESOURCE_TOOL_NAME = "falcon_read_resource";

// Tools that legitimately block longer than the MCP SDK's default 60s request
// timeout. Without a per-call override the transport aborts mid-wait and the
// agent treats a still-propagating sensor as a hard failure (skips to HOLD).
// See mcp_timeout_vs_falcon_wait.
const LONG_RUNNING_TOOL_TIMEOUT_MS: Record<string, number> = {
  // Phase 1.5 propagation wait — eyas-mcp caps timeout_seconds at 600; give
  // the transport headroom over that plus probe upload / cleanup overhead.
  falcon_wait_for_rtr_sessions: 660_000,
};

// Native write tools that stay hidden from the agent. Every one is still
// approval-gated via REQUIRES_APPROVAL (lib/mcp/write-tools.ts); this set only
// decides whether the agent sees the NATIVE tool or Eyas's own tool instead.
// Each entry below has an Eyas tool whose check runs BEFORE the write, and a
// native tool offers no pre-write hook (only suppress / approval-gate /
// post-result), so exposing the native would skip that check:
//   - falcon_create_exclusion: extras_create_ioa_exclusion adds the
//     single-quote reject-don't-escape guard and the /tuning primer wiring.
//   - falcon_create_host_group / falcon_create_policy: the provisioning flows
//     add canonical naming and the {ok,id} auto-save.
//   - falcon_perform_host_group_action: Eyas's extras_host_group_add_members /
//     _remove_members (lib/eyas-tools/host-group-tools.ts) call it with
//     explicit device ids; the IR and Shadow-AI playbooks, the IR release
//     guard, ground truth and run analysis all key on those names.
//   - falcon_delete_policies: Falcon refuses to delete an enabled policy;
//     the extras delete disables first.
//   - falcon_create_data_security_entity: the extras_create_data_protection_*
//     tools apply monitor-first defaults before the write.
//   - falcon_update_exclusion / falcon_set_policy_precedence: no Eyas tool, but
//     held back (a regex update would skip the create-time guard; precedence
//     is fleet-wide).
// The agent biases hard toward falcon_* names over extras_* regardless of
// prompt steering, so suppression is the only reliable way to route to Eyas's
// tool.
//
// Every other native write is ADOPTED: exposed to the agent and gated. That
// includes falcon_update_detections (verdicts are the true_positive /
// false_positive tags on add_tags; it chunks >1000 ids itself) and
// falcon_execute_workflow (takes the definition id and trigger parameters
// verbatim), which replaced extras_update_detection_status and
// extras_workflows_execute. NATIVE_ADOPTED in /audit-write-tools is the
// authoritative list.
//
// /audit-write-tools asserts every suppressed native write is gated AND
// suppressed, every adopted native write is gated AND NOT suppressed, and the two
// sets stay disjoint. Do NOT move a name between categories without updating that
// skill's invariant lists.
export const NATIVE_WRITE_SUPPRESS: ReadonlySet<string> = new Set<string>([
  "falcon_create_exclusion",
  "falcon_update_exclusion",
  "falcon_create_host_group",
  "falcon_perform_host_group_action",
  "falcon_create_policy",
  "falcon_delete_policies",
  "falcon_set_policy_precedence",
  "falcon_create_data_security_entity",
]);

// eyas-mcp's sidecar port baked most of the falcon-extras sidecar into the
// native server as falcon_* READ tools. Each duplicates an extras_* tool that
// routes, playbooks, projections and prompts still call by name, so exposing
// both would let the agent bypass the curated path (it biases toward falcon_*).
// Hidden until its family is migrated one at a time — compare shapes, move
// callers + projections to the native name, expose it, retire the twin — then
// delete the entry here. Native → current twin:
// Native reads deliberately KEPT hidden after a parity check: the sidecar twin
// carries curated behavior the native tool doesn't, and exposing both would
// let the agent (which biases toward falcon_*) take the poorer path.
//   - falcon_get_process_tree → KEEP extras_host_process_tree. Same ancestry
//     (verified live, XDR us-2), but the native delivery_vector is a generic
//     heuristic ("user_executed_file") while the twin runs Eyas's curated
//     classifier ("user_executed_dropper", phishing_doc, lateral_winrm, …) —
//     the vocabulary the IR playbook's Phase 2 branches on — plus per-node
//     verdict / signed annotations the detection drawer renders. Migrates once
//     eyas-mcp ships the same classifier.
export const NATIVE_READ_KEEP: ReadonlySet<string> = new Set<string>([
  "falcon_get_process_tree",
]);

// Arguments the bridge enforces on a native tool, whatever the agent passed.
// falcon_get_host_group_membership defaults to verify="none" (the host record's
// `groups` field, which can lag a static change), but IR Phase 0 captures this
// list and Phase 4 restores it verbatim, so every call checks static groups one
// by one and fails loudly on any error (eyas-mcp ≥ 7fd4031). "all" is kept when
// asked for; "none" / "record" / a missing value become "static".
// See falcon_host_groups_field_unreliable.
export function enforceToolArgs(
  name: string,
  input: Record<string, unknown>,
): Record<string, unknown> {
  if (name === "falcon_get_host_group_membership" && input.verify !== "all") {
    return { ...input, verify: "static" };
  }
  // IR Phase 1.5 waits for the quarantine policy + IOA exclusion to reach the
  // sensor. A session can open before runscript works, so Eyas only ever
  // waits on a real probe script (eyas-mcp ≥ 2703a99; needs RTR Admin write).
  if (name === "falcon_wait_for_rtr_sessions") {
    return { ...input, probe: "runscript" };
  }
  return input;
}

// eyas-mcp tools the agent must not call directly. The RTR script tools are
// what Eyas's patch / cleanup runs execute on (lib/mcp/native-dispatch.ts), but
// the agent reaches them only through extras_rtr_run_patch / _run_cleanup /
// _check_patch_status, so it can never upload script bytes the library didn't
// render. The rest are hidden until their family moves over; delete an entry
// when it does.
export const PENDING_NATIVE_MIGRATION: ReadonlySet<string> = new Set<string>([
  // Bridge-only: Eyas's patch / cleanup runs dispatch through these.
  "falcon_create_rtr_script",
  "falcon_run_rtr_script_on_hosts",
  "falcon_check_rtr_admin_command_status",
  "falcon_delete_rtr_scripts",
  "falcon_search_rtr_scripts",
  // Bridge-only: the on-request bulk close extras_close_all_open_detections_on_host
  // (lib/eyas-tools/ir/closers.ts) runs through it (one approval card, Eyas's
  // verdict + audit comment).
  // IR Phase 4 closure stays ledger-driven through extras_ir_close_remediated.
  "falcon_close_host_detections",
]);

// Native tools that advertise readOnlyHint:false but are INTENTIONALLY ungated
// — the annotation backstop must NOT gate or flag these (mirrors the
// deliberate-omission rationale in lib/mcp/write-tools.ts). falcon-mcp 0.13.0's
// RTR module marks session lifecycle + the read_only command variant
// readOnlyHint:false (establishing/tearing down a session isn't a pure read),
// but they have no host-side write effect and the command variant is
// server-side-restricted to a non-mutating whitelist. Gating them would put
// three approval clicks in front of every "show me running processes"
// investigation. The genuinely destructive RTR tools
// (execute_rtr_active_responder_command / _admin_command) are absent from
// 0.13.0; if a future version adds them, they are NOT in this set, so the
// backstop will gate them (and flag the drift) until they're registered.
const ANNOTATION_GATE_EXEMPT: ReadonlySet<string> = new Set<string>([
  "falcon_init_rtr_session",
  "falcon_pulse_rtr_session",
  "falcon_execute_rtr_read_only_command",
  "falcon_run_rtr_read_only_command_and_wait",
  "falcon_delete_rtr_session",
  // eyas-mcp: the multi-host form of the read-only command — read-only
  // BatchCmd endpoint plus the shared client-side read-only allowlist. Exposed
  // ungated (user decision 2026-11-07), like its single-host sibling.
  "falcon_run_rtr_read_only_command_on_hosts",
  // eyas-mcp: runs a CrowdStrike-published RTR script from the live
  // catalog (host introspection only — Process, Service, RegistryKey, …)
  // through an admin batch session, hence readOnlyHint:false. Same posture
  // as the retired extras_rtr_run_falcon_script, which ran ungated; the
  // native validates the name against the live catalog and json_input.
  "falcon_run_falcon_script",
]);

// Native calls made on the agent's behalf by an Eyas tool (dispatch envelopes
// and lib/eyas-tools). A wrapped upstream error or isError result comes back as
// `error`, never as an empty success.
export function makeCallNative(client: Client): CallNative {
  return async (toolName, args, opts) => {
    try {
      const r = await client.callTool(
        { name: toolName, arguments: args },
        undefined,
        opts?.timeoutMs ? { timeout: opts.timeoutMs } : undefined,
      );
      const objs = parseToolResultObjects<Record<string, unknown>>(
        r.content as Array<{ type: string; text?: string }>,
      );
      const err = detectFalconError(objs);
      if (err) return { obj: null, error: err };
      if (r.isError) {
        const text = (r.content as Array<{ type: string; text?: string }>)
          .map((c) => (c.type === "text" ? c.text ?? "" : ""))
          .join(" ")
          .trim();
        return { obj: null, error: text || `${toolName} failed` };
      }
      return { obj: objs[0] ?? null, error: null };
    } catch (e) {
      return { obj: null, error: e instanceof Error ? e.message : String(e) };
    }
  };
}

/** The context an in-process Eyas tool runs with: native calls on `client`. */
export function makeEyasToolContext(client: Client): EyasToolContext {
  return {
    callNative: makeCallNative(client),
    searchNative: async (name, args) => {
      try {
        const r = await client.callTool({ name, arguments: args });
        const text = (r.content as Array<{ type: string; text?: string }>)
          .map((c) => (c.type === "text" && typeof c.text === "string" ? c.text : ""))
          .join("\n");
        const p = shapeNativePayload(text);
        if (p.scope_pending === true) return { ok: true, scope_pending: true, items: [] };
        if (p.ok !== true) return { ok: false, error: String(p.error ?? `${name} failed`) };
        if (r.isError) return { ok: false, error: text.trim() || `${name} failed` };
        return {
          ok: true,
          items: (Array.isArray(p.items) ? p.items : []) as Record<string, unknown>[],
          total: typeof p.total === "number" ? p.total : undefined,
        } satisfies NativeSearchResult;
      } catch (e) {
        return { ok: false, error: e instanceof Error ? e.message : String(e) };
      }
    },
  };
}

export async function buildToolBridge(
  client: Client,
  extras?: Client | null,
): Promise<ToolBridge> {
  const [toolsResp, resourcesResp, extrasToolsResp] = await Promise.all([
    client.listTools(),
    client.listResources().catch(() => ({ resources: [] as FalconResource[] })),
    extras ? extras.listTools() : Promise.resolve({ tools: [] }),
  ]);

  // Map each tool name back to the client that serves it so invoke() can
  // dispatch correctly. On collision the primary client wins.
  // falcon-mcp 0.10.0 removed the deprecated incidents module and shipped a
  // usable Cases module in its place. Cases are now intentionally exposed to
  // the agent (writes are approval-gated via REQUIRES_APPROVAL, not filtered
  // here). This filter is retained as a defensive backstop only: it still
  // suppresses any residual incident / CrowdScore tool name (the CrowdScore
  // signal drove false-confident "Active threats" conclusions), which also
  // covers the case where an older falcon-mcp is ever resolved from cache.
  // Do NOT extend it to match `case` — that would re-bury the Cases unlock.
  const isIncidentsTool = (n: string) =>
    n.includes("incident") || n.includes("crowd_score") || n.includes("crowdscore");

  // A tool is hidden from the agent if it's an incidents/crowd_score residual
  // OR one of the 0.12.0 native writes we route to the sidecar instead.
  const isSuppressed = (n: string) =>
    isIncidentsTool(n) ||
    NATIVE_WRITE_SUPPRESS.has(n) ||
    NATIVE_READ_KEEP.has(n) ||
    PENDING_NATIVE_MIGRATION.has(n);

  const toolToClient = new Map<string, Client>();
  for (const t of toolsResp.tools) {
    if (isSuppressed(t.name)) continue;
    toolToClient.set(t.name, client);
  }
  for (const t of extrasToolsResp.tools) {
    if (isSuppressed(t.name)) continue;
    // Eyas's in-process tools (lib/eyas-tools) replace a sidecar tool of the
    // same name while the sidecar is being retired.
    if (EYAS_TOOL_MAP.has(t.name)) continue;
    if (!toolToClient.has(t.name)) toolToClient.set(t.name, extras as Client);
  }
  const eyasTools = EYAS_TOOLS.filter((t) => !toolToClient.has(t.name));

  const allTools = [
    ...toolsResp.tools.filter((t) => !isSuppressed(t.name)),
    ...extrasToolsResp.tools.filter(
      (t) => !isSuppressed(t.name) && toolToClient.get(t.name) === extras,
    ),
  ];

  // Fail-closed approval backstop. falcon-mcp 0.13.0 sets MCP tool annotations
  // comprehensively — READ_ONLY_ANNOTATIONS on reads, readOnlyHint:false on
  // every write (destructiveHint:true on deletes). Collect the VISIBLE native
  // writes so the loop can gate any that slipped out of REQUIRES_APPROVAL. Only
  // the native client is annotated; the sidecar (extras_*) sets no annotations
  // and is covered by its own write-shape audit, so it's excluded here.
  const annotatedNativeWrites = new Set<string>();
  for (const t of toolsResp.tools) {
    if (isSuppressed(t.name)) continue;
    if (ANNOTATION_GATE_EXEMPT.has(t.name)) continue;
    if (t.annotations?.readOnlyHint === false) annotatedNativeWrites.add(t.name);
  }

  const unclassifiedSidecarTools = new Set<string>();
  for (const t of allTools) {
    if (toolToClient.get(t.name) !== extras) continue;
    if (REQUIRES_APPROVAL.has(t.name) || EXTRAS_READ_ONLY.has(t.name)) continue;
    unclassifiedSidecarTools.add(t.name);
  }
  // Eyas's in-process tools carry no annotations either; same fail-closed rule.
  for (const t of eyasTools) {
    if (REQUIRES_APPROVAL.has(t.name) || EXTRAS_READ_ONLY.has(t.name)) continue;
    unclassifiedSidecarTools.add(t.name);
  }

  const anthropicTools: Anthropic.Tool[] = [
    ...allTools.map((t) => ({
      name: t.name,
      description: t.description ?? "",
      input_schema: (t.inputSchema as Anthropic.Tool["input_schema"]) ?? {
        type: "object" as const,
        properties: {},
      },
    })),
    ...eyasTools.map((t) => ({
      name: t.name,
      description: t.description,
      input_schema: t.input_schema,
    })),
  ];

  if (resourcesResp.resources.length > 0) {
    anthropicTools.push({
      name: READ_RESOURCE_TOOL_NAME,
      description:
        "Read a Falcon MCP resource by URI. Use this when a tool's description tells you to consult a syntax guide — an FQL guide before constructing a `filter` expression, or the NGSIEM CQL guide before authoring an NGSIEM search — before making the call. Available resource URIs are listed in the system prompt.",
      input_schema: {
        type: "object",
        properties: {
          uri: {
            type: "string",
            description:
              "Resource URI exactly as listed in the system prompt (e.g. 'falcon://detections/search/fql-guide').",
          },
        },
        required: ["uri"],
      },
    });
  }

  const eyasCtx = makeEyasToolContext(client);

  const invoke: ToolBridge["invoke"] = async (name, input) => {
    if (name === READ_RESOURCE_TOOL_NAME) {
      const uri = String(input.uri ?? "");
      if (!uri) {
        return { content: "Missing required `uri` argument.", isError: true };
      }
      const resp = await client.readResource({ uri });
      const text = resp.contents
        .map((c) => ("text" in c && typeof c.text === "string" ? c.text : ""))
        .filter(Boolean)
        .join("\n");
      return { content: text || "(empty resource)", isError: false };
    }

    const eyasTool = EYAS_TOOL_MAP.get(name);
    if (eyasTool && !toolToClient.has(name)) {
      try {
        const r = await eyasTool.run(input, eyasCtx);
        if (eyasTool.rawResult) return r;
        return { content: projectToolResult(name, r.content) || r.content, isError: r.isError };
      } catch (e) {
        return { content: e instanceof Error ? e.message : String(e), isError: true };
      }
    }

    const target = toolToClient.get(name) ?? client;
    const longTimeout = LONG_RUNNING_TOOL_TIMEOUT_MS[name];
    const resp = await target.callTool(
      { name, arguments: enforceToolArgs(name, input) },
      undefined,
      longTimeout ? { timeout: longTimeout } : undefined,
    );
    const rawText = (resp.content as Array<{ type: string; text?: string }>)
      .map((c) => (c.type === "text" && typeof c.text === "string" ? c.text : ""))
      .filter(Boolean)
      .join("\n");
    // Falcon API 500s (rate limit, trace-id error, transient outage) are wrapped
    // by falcon-mcp as isError:false text content. Surfaced unguarded, the agent
    // reads the empty object as "zero detections/hosts" plus a "none dropped,
    // don't refetch" projection note — in IR Phase 0 that silently under-scopes
    // the engagement. Detect the single-object {error,details} envelope and
    // promote it to a real tool error BEFORE projectToolResult reassures.
    // Parse the raw blob ONCE and reuse it for both the error check and the
    // projection — these large payloads (hosts limit 5000, vulns, detections)
    // were being parsed twice per tool call on the hot chat path.
    //
    // Only the falcon-mcp client path goes through detectFalconError. Sidecar
    // (extras) tools return their own structured `{ok:false, error, ...}`
    // payloads — CQL lint failures carry `cql_lint`+`fix`, scope-pending carries
    // staged-build context — and detectFalconError would collapse them to the
    // bare error string, stripping the context the agent needs to self-correct.
    const parsed = parseToolResultObjects<Record<string, unknown>>(
      resp.content as Array<{ type: string; text?: string }>,
    );
    if (target === client) {
      const upstreamError = detectFalconError(parsed);
      if (upstreamError) {
        return { content: upstreamError, isError: true };
      }
    }
    const projected = projectToolResult(name, rawText, parsed);
    return { content: projected || "(empty result)", isError: Boolean(resp.isError) };
  };

  // Sorted so the cached prompt prefix is identical from turn to turn
  // (eyas-mcp's own ordering changes per process — lib/llm/prompt-cache.ts).
  return {
    anthropicTools: canonicalTools(anthropicTools),
    resources: canonicalResources(resourcesResp.resources as FalconResource[]),
    annotatedNativeWrites,
    unclassifiedSidecarTools,
    invoke,
  };
}
