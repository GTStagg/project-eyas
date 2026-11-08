"use client";

import { useEffect, useState } from "react";
import { ChevronRight, GitBranch, AlertTriangle, Loader2 } from "lucide-react";

// Renders the ancestry + descendant tree returned by /api/process-tree
// for a given detection. Headlines the delivery_vector verdict ("how
// did this attack arrive") and surfaces the chain as evidence.
//
// Lazy: nothing is fetched until `enabled` flips to true (typically when
// the parent detection drawer opens). Avoids 5 NGSIEM searches firing
// for a 25-row table on page load.

type ProcessNode = {
  pid?: number;
  ppid?: number;
  os_pid?: number;
  image?: string;
  cmdline?: string;
  user?: string;
  user_sid?: string;
  signed?: boolean | null;
  ts?: unknown;
  depth?: number;
  verdict?: string;
};

type DeliveryVector = {
  kind: string;
  confidence: string;
  rationale: string;
  initial_access_pid?: number;
  initial_access_image?: string;
  weaponized_artifact?: string;
};

type Response = {
  ok: boolean;
  pivot?: { pid?: number; image?: string; cmdline?: string };
  delivery_vector?: DeliveryVector;
  ancestry?: ProcessNode[];
  descendants?: ProcessNode[];
  events_scanned?: number;
  window_widened?: boolean;
  anchor_recovered?: boolean;
  truncated?: boolean;
  error?: string;
};

const VECTOR_TONE: Record<string, string> = {
  phishing_doc: "border-red-800 bg-red-950/40 text-red-200",
  phishing_email_direct: "border-red-800 bg-red-950/40 text-red-200",
  browser_drive_by: "border-orange-800 bg-orange-950/40 text-orange-200",
  archive_extraction: "border-amber-800 bg-amber-950/40 text-amber-200",
  user_executed_dropper: "border-amber-800 bg-amber-950/40 text-amber-200",
  malicious_document_lateral: "border-orange-800 bg-orange-950/40 text-orange-200",
  c2_agent: "border-red-800 bg-red-950/40 text-red-200",
  lateral_winrm: "border-rose-800 bg-rose-950/40 text-rose-200",
  lateral_psexec: "border-rose-800 bg-rose-950/40 text-rose-200",
  scheduled_task_persistence: "border-sky-800 bg-sky-950/40 text-sky-200",
  wmi_persistence: "border-sky-800 bg-sky-950/40 text-sky-200",
  malicious_service: "border-sky-800 bg-sky-950/40 text-sky-200",
  lolbin_initial: "border-neutral-700 bg-neutral-900 text-neutral-300",
  unknown: "border-neutral-700 bg-neutral-900 text-neutral-400",
};

const CONFIDENCE_LABEL: Record<string, string> = {
  high: "high confidence",
  medium: "medium confidence",
  low: "low confidence",
};

function basename(image?: string): string {
  if (!image) return "—";
  const parts = image.split(/[\\/]/);
  return parts[parts.length - 1] || image;
}

function vectorHeadline(kind: string): string {
  switch (kind) {
    case "phishing_doc":
      return "Phishing document";
    case "phishing_email_direct":
      return "Phishing email (direct attachment)";
    case "browser_drive_by":
      return "Browser drive-by";
    case "archive_extraction":
      return "User-extracted archive";
    case "user_executed_dropper":
      return "User-executed dropper";
    case "malicious_document_lateral":
      return "Malicious document (non-email source)";
    case "c2_agent":
      return "C2 agent / implant";
    case "lateral_winrm":
      return "Lateral movement: WinRM";
    case "lateral_psexec":
      return "Lateral movement: PsExec / SMB";
    case "scheduled_task_persistence":
      return "Persistence: Scheduled Task";
    case "wmi_persistence":
      return "Persistence: WMI subscription";
    case "malicious_service":
      return "Persistence: Windows Service";
    case "lolbin_initial":
      return "LOLBin entry (chain truncated)";
    case "unknown":
    default:
      return "Delivery vector unknown";
  }
}

export default function ProcessTree({
  deviceId,
  pivotPid,
  pivotImage,
  pivotTsIso,
  enabled,
}: {
  deviceId: string;
  pivotPid?: number;
  pivotImage?: string;
  pivotTsIso: string;
  enabled: boolean;
}) {
  const [data, setData] = useState<Response | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (!enabled || data || loading) return;
    if (!pivotPid && !pivotImage) {
      setErr(
        "No pivot pid or image on this detection. Process-tree reconstruction skipped.",
      );
      return;
    }
    setLoading(true);
    const params = new URLSearchParams({
      device_id: deviceId,
      pivot_ts_iso: pivotTsIso,
    });
    if (pivotPid !== undefined) params.set("pivot_pid", String(pivotPid));
    if (pivotImage) params.set("pivot_image", pivotImage);

    fetch(`/api/process-tree?${params.toString()}`)
      .then((r) => r.json())
      .then((j: Response) => {
        if (!j.ok) {
          setErr(j.error ?? "Process-tree call failed");
        } else {
          setData(j);
        }
      })
      .catch((e) => setErr(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false));
  }, [enabled, deviceId, pivotPid, pivotImage, pivotTsIso, data, loading]);

  if (!enabled) return null;

  return (
    <div className="rounded-md border border-neutral-800 bg-neutral-950/60 p-3">
      <div className="mb-2 flex items-center gap-2 text-xs uppercase tracking-wider text-neutral-500">
        <GitBranch className="h-3.5 w-3.5" strokeWidth={1.75} />
        Process tree · delivery vector
      </div>

      {loading && (
        <div className="flex items-center gap-2 text-sm text-neutral-400">
          <Loader2 className="h-4 w-4 animate-spin" />
          Reconstructing ancestry from NGSIEM ProcessRollup2…
        </div>
      )}

      {err && !loading && (
        <div className="flex items-start gap-2 rounded border border-amber-900/60 bg-amber-950/30 p-2 text-sm text-amber-200">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" strokeWidth={1.75} />
          <span>{err}</span>
        </div>
      )}

      {data && data.ok && (
        <DataView data={data} />
      )}
    </div>
  );
}

function DataView({ data }: { data: Response }) {
  const v = data.delivery_vector;
  const tone = (v && VECTOR_TONE[v.kind]) ?? VECTOR_TONE.unknown;

  return (
    <div className="space-y-3">
      {v && (
        <div className={`rounded border p-3 ${tone}`}>
          <div className="flex items-baseline justify-between gap-2">
            <div className="text-sm font-semibold">{vectorHeadline(v.kind)}</div>
            <div className="font-mono text-[10px] uppercase tracking-[0.14em] opacity-80">
              {CONFIDENCE_LABEL[v.confidence] ?? v.confidence}
            </div>
          </div>
          <div className="mt-1 text-xs leading-relaxed opacity-90">{v.rationale}</div>
          {v.weaponized_artifact && (
            <div className="mt-2 truncate font-mono text-[11px] opacity-80">
              <span className="opacity-60">artifact </span>
              {v.weaponized_artifact}
            </div>
          )}
        </div>
      )}

      <div>
        <div className="mb-1 text-[11px] uppercase tracking-wider text-neutral-500">
          Ancestry (root → pivot)
        </div>
        <ol className="space-y-0.5">
          {(data.ancestry ?? []).slice().reverse().map((node, i) => (
            <NodeRow key={`a-${node.pid}-${i}`} node={node} indent={i} isPivot={i === (data.ancestry?.length ?? 1) - 1} />
          ))}
        </ol>
      </div>

      {(data.descendants?.length ?? 0) > 0 && (
        <div>
          <div className="mb-1 text-[11px] uppercase tracking-wider text-neutral-500">
            Descendants ({data.descendants?.length ?? 0}
            {data.truncated ? "+" : ""}) · blast radius
          </div>
          <ol className="space-y-0.5">
            {(data.descendants ?? []).map((node, i) => (
              <NodeRow
                key={`d-${node.pid}-${i}`}
                node={node}
                indent={node.depth ?? 1}
                isPivot={false}
              />
            ))}
          </ol>
        </div>
      )}

      <div className="flex flex-wrap gap-3 pt-1 font-mono text-[10px] uppercase tracking-[0.14em] text-neutral-600">
        <span>events scanned {data.events_scanned ?? 0}</span>
        {data.window_widened && (
          <span className="text-amber-400">window widened ±60m for parent lookup</span>
        )}
        {data.anchor_recovered && (
          <span className="text-amber-400">window re-anchored on actual process start (alert fired well after launch)</span>
        )}
      </div>
    </div>
  );
}

function NodeRow({
  node,
  indent,
  isPivot,
}: {
  node: ProcessNode;
  indent: number;
  isPivot: boolean;
}) {
  const padding = Math.min(indent, 8) * 12;
  const verdictTone =
    node.verdict === "initial-access-anchor"
      ? "border-l-2 border-l-red-500 bg-red-950/30"
      : node.verdict === "c2-agent"
      ? "border-l-2 border-l-red-500 bg-red-950/30"
      : node.verdict === "office-with-doc"
      ? "border-l-2 border-l-orange-500 bg-orange-950/20"
      : node.verdict === "lolbin"
      ? "border-l-2 border-l-amber-500 bg-amber-950/15"
      : node.verdict === "signed-system"
      ? "border-l-2 border-l-neutral-700"
      : "border-l-2 border-l-transparent";
  const pivotRing = isPivot ? "ring-1 ring-red-700/60" : "";

  return (
    <li
      className={`flex items-start gap-2 rounded px-2 py-1 font-mono text-[12px] ${verdictTone} ${pivotRing}`}
      style={{ paddingLeft: `${8 + padding}px` }}
    >
      <ChevronRight className="mt-0.5 h-3 w-3 shrink-0 text-neutral-600" strokeWidth={2} />
      <div className="min-w-0 flex-1">
        <div className="flex items-baseline gap-2">
          <span className="font-semibold text-neutral-100">{basename(node.image)}</span>
          <span className="text-[10px] text-neutral-500">pid {node.os_pid ?? node.pid ?? "?"}</span>
          {node.user && (
            <span className="text-[10px] text-neutral-500">· {node.user}</span>
          )}
          {isPivot && (
            <span className="rounded bg-red-900/60 px-1.5 text-[9px] uppercase tracking-wider text-red-200">
              pivot
            </span>
          )}
        </div>
        {node.cmdline && (
          <div className="truncate text-[11px] text-neutral-400">{node.cmdline}</div>
        )}
      </div>
    </li>
  );
}
