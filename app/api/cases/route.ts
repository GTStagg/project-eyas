import { NextResponse } from "next/server";
import { withFalconMcpClient } from "@/lib/mcp/falcon-client";
import { parseConcatenatedJson, detectFalconError, isScopeDenied } from "@/lib/mcp/parse";
import { fail } from "@/lib/api/respond";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Dashboard fetcher for Falcon Cases (falcon-mcp 0.10.0 cases module). No
// LLM — calls falcon_search_cases directly, normalizes server-side, renders
// raw (the agent-path projection in lib/mcp/projections.ts is separate).
//
// Cases:read is NOT in this tenant's granted scopes, so the dominant state
// is scope-pending. Upstream falcon-mcp packages a scope denial as an
// {error, details} JSON envelope with isError:false (detectFalconError
// catches the HTTP-wrapped form; the string match catches the bare 403
// message), which we translate into the same { ok, scope_pending } shape
// the staged pages (/prevention, /identity) already use.

type RawCase = Record<string, unknown>;

type CaseRow = {
  id: string;
  reference_id?: string;
  name: string;
  status: string;
  severity: number;
  created_timestamp?: string;
  updated_timestamp?: string;
  assigned_to_name?: string;
  description?: string;
  tags: string[];
  alert_evidence_count: number;
  event_evidence_count: number;
};

const str = (v: unknown): string | undefined =>
  typeof v === "string" && v.trim() ? v : undefined;
const num = (v: unknown): number | undefined =>
  typeof v === "number" && Number.isFinite(v) ? v : undefined;
const get = (o: RawCase, path: string): unknown => {
  let cur: unknown = o;
  for (const p of path.split(".")) {
    if (cur && typeof cur === "object" && p in (cur as RawCase)) {
      cur = (cur as RawCase)[p];
    } else return undefined;
  }
  return cur;
};
// Upstream `entities_cases_post_v2` returns evidence as
// `evidence.alerts.records[]` / `evidence.events.records[]`, NOT flat arrays.
// Walk the nested shape but stay tolerant of older/agent-path projections that
// already flattened it.
const countEvidence = (c: RawCase, kind: string): number => {
  const ev = c.evidence as RawCase | undefined;
  const bucket = ev?.[kind];
  if (Array.isArray(bucket)) return bucket.length;
  if (bucket && typeof bucket === "object") {
    const records = (bucket as RawCase).records;
    if (Array.isArray(records)) return records.length;
  }
  const flat = c[kind];
  return Array.isArray(flat) ? flat.length : 0;
};

function normalize(c: RawCase): CaseRow | null {
  const id = str(c.id);
  if (!id) return null;
  return {
    id,
    reference_id: str(c.reference_id),
    name: str(c.name) ?? "(untitled case)",
    status: str(c.status) ?? "unknown",
    severity: num(c.severity) ?? 0,
    created_timestamp: str(c.created_timestamp),
    updated_timestamp: str(c.updated_timestamp),
    assigned_to_name:
      str(c.assigned_to_name) ??
      str(c.assigned_to) ??
      str(c.assignee) ??
      str(get(c, "assigned_to.name")),
    description: str(c.description),
    tags: Array.isArray(c.tags) ? c.tags.filter((t): t is string => typeof t === "string") : [],
    alert_evidence_count: countEvidence(c, "alerts"),
    event_evidence_count: countEvidence(c, "events"),
  };
}

// Scope-denial detection is shared with probeFalconMcp() via isScopeDenied()
// (lib/mcp/parse.ts), so the nav capability gate and this page can't disagree
// on scope state.

// Operator-facing error copy. Raw upstream strings (500 bodies, FQL parse
// errors, endpoint names) are logged server-side, never rendered.
const CASES_ERROR_MESSAGE =
  "Couldn't load cases from Falcon right now. Refresh to try again; if it persists, check the Falcon connection on the status page.";

export async function GET() {
  try {
    const payload = await withFalconMcpClient(async (client) => {
      const result = await client.callTool({
        name: "falcon_search_cases",
        arguments: { limit: 200, sort: "created_timestamp.desc" },
      });

      const text = (result.content as Array<{ type: string; text?: string }>)
        .map((c) => (c.type === "text" && c.text ? c.text : ""))
        .join("\n");

      // Scope denial first. isScopeDenied keys on the structured signal
      // (details.status_code 403/401 or required_scopes) with a raw-text
      // fallback, so it survives the cases FQL-error envelope (error dict
      // nested under results[0] + appended guide) that a bare substring or
      // detectFalconError length===1 check misses. The same detector backs
      // the capability probe.
      if (isScopeDenied(text)) {
        return {
          ok: true,
          scope_pending: true,
          note: "The Falcon API client does not carry the Cases (Read) scope.",
        };
      }

      const parsed = parseConcatenatedJson<RawCase>(text);

      // Other upstream Falcon API errors (500s, malformed FQL, etc.). Log the
      // raw upstream string server-side for diagnosis, but hand the operator a
      // fixed plain-language message.
      const errMsg = detectFalconError(parsed);
      if (errMsg) {
        console.error("[cases] upstream Falcon error:", errMsg);
        return { ok: false, error: CASES_ERROR_MESSAGE };
      }

      const items = parsed
        .map(normalize)
        .filter((c): c is CaseRow => c !== null)
        // Severity-desc with created_timestamp.desc as tiebreaker — operators
        // want the highest-severity cases first, not freshest. Upstream
        // queries_cases_get_v1 + entities_cases_post_v2 preserve the query
        // sort, so this is a deterministic re-sort on the row set.
        .sort((a, b) => {
          if (b.severity !== a.severity) return b.severity - a.severity;
          const at = a.created_timestamp ? Date.parse(a.created_timestamp) : 0;
          const bt = b.created_timestamp ? Date.parse(b.created_timestamp) : 0;
          return bt - at;
        });

      const summary = {
        total: items.length,
        open: items.filter(
          (c) => c.status === "new" || c.status === "in_progress" || c.status === "reopened",
        ).length,
        unassigned: items.filter((c) => !c.assigned_to_name).length,
        high_sev: items.filter((c) => c.severity >= 75).length,
      };

      return { ok: true, items, summary };
    });

    return NextResponse.json(payload);
  } catch (err) {
    console.error("[cases] failed:", err);
    return fail(CASES_ERROR_MESSAGE, 502);
  }
}
