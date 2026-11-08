import { NextResponse } from "next/server";
import { withFalconExtrasClient } from "@/lib/mcp/falcon-extras-client";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Read-only sidecar passthrough: reconstructs ProcessRollup2 ancestry +
// descendants around a detection pivot and returns the delivery_vector
// classifier verdict. Surfaces in the detection drawer below the Command
// line block — the verdict is the headline ("Delivery vector: phishing
// document — OUTLOOK.EXE → WINWORD.EXE opened Q1-Invoice.docm"), the
// ancestry/descendant lists are the evidence pane.

type ProcessTreeResponse = {
  ok: boolean;
  pivot?: { pid?: number; image?: string; cmdline?: string; ts?: unknown };
  delivery_vector?: {
    kind: string;
    confidence: string;
    rationale: string;
    initial_access_pid?: number;
    initial_access_image?: string;
    weaponized_artifact?: string;
  };
  ancestry?: Array<Record<string, unknown>>;
  descendants?: Array<Record<string, unknown>>;
  unaccounted_pids?: number[];
  events_scanned?: number;
  window_widened?: boolean;
  anchor_recovered?: boolean;
  truncated?: boolean;
  error?: string;
};

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const deviceId = (searchParams.get("device_id") ?? "").trim();
  const pivotTsIso = (searchParams.get("pivot_ts_iso") ?? "").trim();
  const pivotPidRaw = searchParams.get("pivot_pid");
  const pivotImage = (searchParams.get("pivot_image") ?? "").trim() || undefined;
  const windowMinutes = Number(searchParams.get("window_minutes") ?? "10");

  if (!/^[a-fA-F0-9]{32}$/.test(deviceId)) {
    return NextResponse.json(
      { ok: false, error: "device_id must be a 32-char hex AID" },
      { status: 400 },
    );
  }
  if (!pivotTsIso) {
    return NextResponse.json(
      { ok: false, error: "pivot_ts_iso required" },
      { status: 400 },
    );
  }
  const pivotPid = pivotPidRaw && /^\d+$/.test(pivotPidRaw) ? Number(pivotPidRaw) : undefined;
  if (pivotPid === undefined && !pivotImage) {
    return NextResponse.json(
      { ok: false, error: "pivot_pid or pivot_image required" },
      { status: 400 },
    );
  }

  try {
    const result = await withFalconExtrasClient<ProcessTreeResponse>(
      async (client) => {
        const args: Record<string, unknown> = {
          device_id: deviceId,
          pivot_ts_iso: pivotTsIso,
          window_minutes: Number.isFinite(windowMinutes) ? windowMinutes : 10,
        };
        if (pivotPid !== undefined) args.pivot_pid = pivotPid;
        if (pivotImage) args.pivot_image = pivotImage;

        const r = await client.callTool({
          name: "extras_host_process_tree",
          arguments: args,
        });
        const text = (r.content as Array<{ type: string; text?: string }>)
          .map((c) => (c.type === "text" && c.text ? c.text : ""))
          .join("\n");
        try {
          return JSON.parse(text) as ProcessTreeResponse;
        } catch {
          return { ok: false, error: "Sidecar returned non-JSON payload" };
        }
      },
    );

    return NextResponse.json(result, {
      status: result?.ok ? 200 : 502,
    });
  } catch (err) {
    return NextResponse.json(
      { ok: false, error: err instanceof Error ? err.message : String(err) },
      { status: 502 },
    );
  }
}
