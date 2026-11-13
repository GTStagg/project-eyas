import { NextResponse } from "next/server";
import Anthropic from "@anthropic-ai/sdk";
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { runSubAgent, type SubAgentResult } from "@/lib/chat/sub-agent";
import { streamAgent } from "@/lib/chat/stream-agent";
import { beginInFlight, endInFlight } from "@/lib/chat/in-flight";
import { withFalconMcpClient } from "@/lib/mcp/falcon-client";
import { parseConcatenatedJson } from "@/lib/mcp/parse";
import { getAnthropicClient, getAnthropicModel } from "@/lib/llm/anthropic";
import { streamMessage } from "@/lib/llm/messages";
import { logUsage } from "@/lib/cost/log";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// `/investigate` runs three data-gathering subagents in parallel — each with
// its own MCP client pair (true concurrency: falcon-mcp serializes per
// client per the persistent-singleton lesson, so parallelism comes from
// spawning multiple clients). Then a synthesis turn streams the final
// risk-assessment + recommended-actions sections atop the assembled slices.
//
// Why subagents here:
// - Three slices are naturally independent (host-fingerprint reads, threat
//   reads, live-host RTR). One agent walking serially burns wall-clock for
//   no reason; three subagents → wall-clock = max(slice) instead of
//   sum(slices). On the demo path this typically halves end-to-end time.
// - Each subagent gets a focused prompt + a small tool subset, so the cache
//   per slice is independent and stable. Bigger union of cached prefixes
//   beats the previous monolithic prompt's cache footprint.
// - Read-only by tool selection: each subagent's `toolFilter` excludes any
//   write-shape tool. Defense-in-depth beyond the registry's approval gate.

// Tool subset filters per subagent.
const FINGERPRINT_TOOLS = new Set([
  "falcon_search_hosts",
]);

const THREATS_TOOLS = new Set([
  "falcon_search_detections",
  "falcon_search_vulnerabilities",
  "falcon_get_threatgraph_ran_on",
]);

const POSTURE_TOOLS = new Set([
  // RTR session lifecycle + read-only commands (bridge names carry the
  // falcon_ prefix; without it the toolFilter drops them and the posture
  // subagent silently loses live-RTR access).
  "falcon_init_rtr_session",
  "falcon_execute_rtr_read_only_command",
  "falcon_delete_rtr_session",
  "falcon_pulse_rtr_session",
  // CrowdStrike-published falconscripts (read-only catalog)
  "falcon_run_falcon_script",
  "falcon_list_falcon_scripts",
  // Need host record for OS + RTR-state gating
  "falcon_search_hosts",
]);

function fingerprintPrompt(): string {
  return [
    "You are gathering host-fingerprint facts for a single host. Do exactly this:",
    "1. Call `falcon_search_hosts` with `filter: \"hostname:'<HOSTNAME>'\"` (limit 1).",
    "2. From the response, render an H2 'Host fingerprint' Markdown section listing: hostname, platform_name + os_version, external_ip + local_ip, last_seen, status, rtr_state, agent_version. Use a compact 2-column table or a bulleted list — your choice, whichever is more readable for the values you got.",
    "If the host record is empty, render the H2 with the line 'Host not found in tenant.' and stop.",
    "OUTPUT: Markdown section only. No preamble, no narration, no trailing commentary. Start with the `## Host fingerprint` heading.",
  ].join("\n");
}

function threatsPrompt(): string {
  const today = new Date().toISOString().slice(0, 10);
  return [
    `You are gathering recent threat activity for a single host. Today is ${today} UTC.`,
    "",
    "ROUND 1 — fire both in parallel:",
    "- `falcon_search_detections` with `filter: \"device.hostname:'<HOSTNAME>'\"`, limit 25, sort `created_timestamp.desc`.",
    "- `falcon_search_vulnerabilities` with `facet: \"cve\"` (REQUIRED — without it rows have no CVE id, severity, or product) and `filter: \"status:'open'+aid:'<DEVICE_ID>'\"`, limit 25, using the device_id from the user message. If the user message has no device_id, skip this call and write 'Vulnerabilities unavailable — the host id could not be resolved.' under the Open vulnerabilities heading.",
    "",
    "ROUND 2 (only if Round 1's detections surfaced one or more SHA-256 hashes in `behaviors[].sha256` or top-level `sha256`): pick at most TWO of the highest-severity hashes and call `falcon_get_threatgraph_ran_on` once per hash with `value=<hash>`, `indicator_type='sha256'`, `limit=50`. This enumerates other tenant hosts that ran the same binary — load-bearing for blast-radius. Do NOT run more than two — token budget. Skip entirely on a permission or other error.",
    "",
    "OUTPUT: render these three H2 Markdown sections, in this exact order:",
    "- `## Recent detection activity` — table of detections (severity / tactic · technique / time / cmdline summary). 'No recent detections' if none.",
    "- `## Open vulnerabilities` — table of CVEs (severity / CVSS / product / detected). 'No open vulnerabilities' if none.",
    "- `## Lateral spread` — only if Round 2 ran with results. For each hash queried: hash (truncated to 12 chars) | other hosts that ran it (count + first three hostnames). One line each. If a hash returned zero other hosts: 'isolated to this host.' If Round 2 was skipped or errored: omit the section entirely.",
    "",
    "DISCIPLINE: no preamble, no narration, no trailing commentary. Start with the `## Recent detection activity` heading. Be decisive — if something looks suspicious in the cmdline, name it.",
  ].join("\n");
}

function posturePrompt(): string {
  return [
    "You are gathering live-host posture for a single host. Decide what to do based on the host record's online/RTR state.",
    "",
    "Step 1: call `falcon_search_hosts` with `filter: \"hostname:'<HOSTNAME>'\"` (limit 1) to get rtr_state and platform_name.",
    "",
    "Step 2 — branch:",
    "- If `rtr_state` is enabled AND `last_seen` is recent (<24h): open an RTR session via `init_rtr_session`, run `ps` via `execute_rtr_read_only_command`, capture top processes, close the session via `delete_rtr_session` (always — even on error path).",
    "- Otherwise: skip the RTR section entirely. The host is offline or RTR-disabled.",
    "",
    "Step 3 — branch (Windows only):",
    "- If the host is Windows AND online: call `falcon_run_falcon_script` twice in parallel: once with `script_name='RegisteredAV'`, once with `script_name='BitLocker'`, both with `device_ids=[<aid>]`. Read-only Falcon-published scripts; structured live-host state.",
    "- Otherwise: skip the defensive-posture section.",
    "",
    "OUTPUT: render up to two H2 Markdown sections:",
    "- `## Live process snapshot` — top ~10 notable processes from RTR `ps`, skipping uninteresting system processes (svchost, csrss, wininit, idle, kernel_task, etc.). 'Host offline — RTR unavailable.' if Step 2 was skipped or failed.",
    "- `## Defensive posture` — Windows hosts only. One line each for AV product (from RegisteredAV) and BitLocker status. Omit the section entirely on non-Windows or if Step 3 was skipped.",
    "",
    "DISCIPLINE: no preamble, no narration. Start with the `## Live process snapshot` heading. If both steps were skipped, output a single line: '_No live-host posture available — host offline or RTR disabled._'",
  ].join("\n");
}

const SYNTHESIS_PROMPT = [
  "You are synthesizing a host investigation. The body of the report is already written — you receive the rendered slices below. Your job is to add the closing two sections.",
  "",
  "OUTPUT: exactly two H2 Markdown sections, in this order:",
  "- `## Risk assessment` — 2-4 sentences. Synthesize across the slices: any detections related to open vulns? Suspicious processes? Stale check-in? Factor in lateral spread — if other hosts ran the same hash, the blast radius isn't this host alone.",
  "- `## Recommended actions` — 3-5 numbered concrete next steps if anything looks off. 'No action required.' if everything is clean.",
  "",
  "Be decisive. If something is suspicious, name it. No preamble, no narration. Start with the `## Risk assessment` heading.",
].join("\n");

type Body = { hostname?: string };

// Spotlight rejects `host_info.hostname` as a filter field, so the threats
// slice needs the host's device id to find its vulnerabilities. Resolved here
// on the slice's own client rather than asking the agent to chain the lookup.
// The hostname is interpolated into FQL, so it is reject-validated, not escaped.
const HOSTNAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/;
async function resolveDeviceId(mcp: Client, hostname: string): Promise<string | null> {
  if (!HOSTNAME_RE.test(hostname)) return null;
  try {
    const result = await mcp.callTool({
      name: "falcon_search_hosts",
      arguments: { filter: `hostname:'${hostname}'`, limit: 1 },
    });
    const text = (result.content as Array<{ type: string; text?: string }>)
      .map((c) => (c.type === "text" && c.text ? c.text : ""))
      .join("\n");
    const id = parseConcatenatedJson<{ device_id?: string }>(text).find((r) => r.device_id)?.device_id;
    return id && /^[0-9a-f]{32}$/i.test(id) ? id : null;
  } catch {
    return null;
  }
}

export async function POST(request: Request) {
  const body = (await request.json().catch(() => ({}))) as Body;
  const hostname = (body.hostname ?? "").trim();
  if (!hostname) {
    return NextResponse.json(
      { ok: false, error: "hostname required" },
      { status: 400 },
    );
  }

  // Mark the process busy for the whole investigation. /investigate drives its
  // own subagents + synthesis call (not runAgentLoop, which self-brackets), so
  // without this the env switcher's isBusy() check would let a credential
  // rotation land mid-run and attribute slices to the wrong tenant. Released
  // when the stream settles (normal completion, error, or client disconnect).
  beginInFlight();
  return streamAgent(async ({ emit, signal }) => {
    emit("ready", { tool_count: 0, resource_count: 0, model: getAnthropicModel() });

    // No real-time progress text during the parallel phase — subagents are
    // intentionally silent. The UI's thinking-spinner covers the wait
    // (~5-10s typical), then forwarded tool events + assembled body +
    // synthesis stream paint the report. Total wall-clock is shorter than
    // the previous serial walk, so silent-then-flurry beats narrate-then-
    // narrate-again on UX.

    // Native client sharing across the fan-out (opt-in, EYAS_POOL_SUBAGENT_MCP=1).
    // falcon-mcp 0.16.0 (#478, offload_to_thread) made the upstream server handle
    // concurrent requests on ONE connection, so the three native clients can
    // collapse to a single shared falcon-mcp client — a live probe measured
    // ~2.4x faster warm at this concurrency with 0 errors, and it saves 2 process
    // spawns + 2 OAuth token mints per investigate. Fan-out is single-turn +
    // single-tenant, so there's no active-env cred-freeze concern.
    // Default OFF preserves the per-subagent native client while the change soaks;
    // see mcp_persistent_singleton + falcon_mcp_v0_16_upgrade.
    const poolNativeClient = process.env.EYAS_POOL_SUBAGENT_MCP === "1";

    const userPrompt = (slice: string, deviceId?: string | null) =>
      `Host hostname: ${hostname}.${deviceId ? ` Host device_id: ${deviceId}.` : ""} Run the ${slice} slice on this host.`;

    // One subagent slice on a supplied (possibly shared) native client.
    const runSlice = (
      mcp: Client,
      slice: "fingerprint" | "threats" | "posture",
      systemPrompt: string,
      filter: Set<string>,
      deviceId?: string | null,
    ): Promise<SubAgentResult> =>
      runSubAgent({
        mcp,
        systemPrompt,
        userPrompt: userPrompt(slice, deviceId),
        toolFilter: (name) => filter.has(name),
        maxIterations: slice === "threats" ? 8 : 6,
        maxTokensPerTurn: 4096,
        surface: `investigate:${slice}` as const,
        signal,
      });

    const runAllSlices = (mcp: Client): Promise<SubAgentResult[]> =>
      Promise.all([
        runSlice(mcp, "fingerprint", fingerprintPrompt(), FINGERPRINT_TOOLS),
        resolveDeviceId(mcp, hostname).then((id) => runSlice(mcp, "threats", threatsPrompt(), THREATS_TOOLS, id)),
        runSlice(mcp, "posture", posturePrompt(), POSTURE_TOOLS),
      ]);

    let fingerprint: SubAgentResult, threats: SubAgentResult, posture: SubAgentResult;
    try {
      if (poolNativeClient) {
        // One shared native client.
        [fingerprint, threats, posture] = await withFalconMcpClient(runAllSlices);
      } else {
        // Default: each subagent gets its OWN native client.
        [fingerprint, threats, posture] = await Promise.all([
          withFalconMcpClient((mcp) => runSlice(mcp, "fingerprint", fingerprintPrompt(), FINGERPRINT_TOOLS)),
          withFalconMcpClient(async (mcp) =>
            runSlice(mcp, "threats", threatsPrompt(), THREATS_TOOLS, await resolveDeviceId(mcp, hostname)),
          ),
          withFalconMcpClient((mcp) => runSlice(mcp, "posture", posturePrompt(), POSTURE_TOOLS)),
        ]);
      }
    } catch (err) {
      if (err instanceof Error && err.name === "AbortError") return;
      emit("error", { message: err instanceof Error ? err.message : String(err) });
      return;
    }

    if (signal?.aborted) return;

    // Forward each subagent's tool calls as synthetic tool_use + tool_result
    // pairs so the existing trace UI (the demo's main learning value)
    // continues to surface the actual Falcon calls. Done after the subagent
    // completes — three subagents finish near-simultaneously, so the user
    // sees a flurry of trace entries appear, then the body. Per-call ids
    // are namespaced (`<slice>-<i>`) to avoid collision across subagents.
    const slices = [
      { name: "fingerprint", r: fingerprint },
      { name: "threats", r: threats },
      { name: "posture", r: posture },
    ];
    for (const { name, r } of slices) {
      r.toolCalls.forEach((tc, i) => {
        const id = `${name}-${i}`;
        emit("tool_use", { id, name: tc.name, input: tc.input });
        emit("tool_result", {
          tool_use_id: id,
          content: tc.output,
          is_error: tc.is_error,
          duration_ms: tc.duration_ms,
        });
      });
      emit("subagent_completed", {
        name,
        iterations: r.iterations,
        tool_calls: r.toolCalls.length,
        duration_ms: r.duration_ms,
        ended_normally: r.endedNormally,
        usage: r.usage,
      });
    }

    // Stream the assembled body first — three rendered slices in order.
    const body = [fingerprint.text, threats.text, posture.text]
      .filter((t) => t && t.trim())
      .join("\n\n");
    emit("text", body);
    emit("text", "\n\n");

    // Synthesis pass — no tools, just composition over the three slices.
    // Streamed so the user sees the closing sections paint live (consistent
    // with prior /investigate UX).
    const anthropic = getAnthropicClient();
    let totalTokens = {
      input_tokens: 0,
      output_tokens: 0,
      cache_creation_input_tokens: 0,
      cache_read_input_tokens: 0,
    };
    try {
      const synthInput: Anthropic.Beta.BetaMessageParam[] = [
        {
          role: "user",
          content: [
            `Host: ${hostname}`,
            "",
            "Slices already rendered:",
            "",
            body,
            "",
            "Now produce the closing two sections.",
          ].join("\n"),
        },
      ];
      const final = await streamMessage(
        anthropic,
        {
          model: getAnthropicModel(),
          max_tokens: 1024,
          system: [
            { type: "text", text: SYNTHESIS_PROMPT, cache_control: { type: "ephemeral", ttl: "1h" } },
          ],
          messages: synthInput,
        },
        {
          signal,
          onEvent: (event) => {
            if (event.type === "content_block_delta" && event.delta.type === "text_delta") {
              emit("text", event.delta.text);
            }
          },
        },
      );
      const u = final.usage;
      if (u) {
        totalTokens = {
          input_tokens: u.input_tokens ?? 0,
          output_tokens: u.output_tokens ?? 0,
          cache_creation_input_tokens: u.cache_creation_input_tokens ?? 0,
          cache_read_input_tokens: u.cache_read_input_tokens ?? 0,
        };
      }
    } catch (err) {
      if (err instanceof Error && err.name === "AbortError") return;
      emit("error", { message: err instanceof Error ? err.message : String(err) });
      return;
    }

    void logUsage({
      ts: new Date().toISOString(),
      model: getAnthropicModel(),
      surface: "investigate",
      iterations: 1,
      usage: totalTokens,
    });

    // Aggregate done event — total iterations + summed usage across all
    // four LLM calls (3 subagents + synthesis). The UI uses this to mark
    // the run complete and stop the spinner.
    const totalIter =
      fingerprint.iterations + threats.iterations + posture.iterations + 1;
    const summed = [fingerprint.usage, threats.usage, posture.usage, totalTokens].reduce(
      (acc, u) => ({
        input_tokens: acc.input_tokens + u.input_tokens,
        output_tokens: acc.output_tokens + u.output_tokens,
        cache_creation_input_tokens:
          acc.cache_creation_input_tokens + u.cache_creation_input_tokens,
        cache_read_input_tokens:
          acc.cache_read_input_tokens + u.cache_read_input_tokens,
      }),
      {
        input_tokens: 0,
        output_tokens: 0,
        cache_creation_input_tokens: 0,
        cache_read_input_tokens: 0,
      },
    );
    emit("done", {
      stop_reason: "end_turn",
      usage: summed,
      iterations: totalIter,
      turn_count: totalIter,
    });
  }, { onSettled: endInFlight });
}
