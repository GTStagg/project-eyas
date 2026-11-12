// Run Eyas tools' Falcon writes through eyas-mcp's native tools.
//
// Patch / cleanup scripts (below) and the on-request bulk close of a host's
// detections (close_host_detections → falcon_close_host_detections).
//
// Eyas validates and renders; a live run is carried out here with eyas-mcp:
//
//   rtr_script → falcon_create_rtr_script (one-off private upload)
//              → falcon_run_rtr_script_on_hosts (`runscript -CloudFile=`)
//              → falcon_delete_rtr_scripts (always, even when the run failed)
//   rtr_status → falcon_check_rtr_admin_command_status
//
// The in-process RTR tools (lib/eyas-tools/rtr-tools.ts) build the envelope
// and call runDispatch directly. The sidecar's bulk close still returns a
// `dispatch` envelope that the tool bridge hands here (DISPATCH_TOOLS).
//
// The result keeps the shape the sidecar used to return (results[] with
// device_id / ok / stdout / stderr / exit_code / error / cloud_request_id /
// complete), so prompts, the IR ledger and the UI read it unchanged. An
// envelope never reaches the agent, and the agent never supplies script
// bytes: only Eyas's library renders them, for approval-gated runs.
//
// Pure apart from the injected `callNative`, so it is unit-tested with a fake
// (scripts/test-native-dispatch.mjs).

type Obj = Record<string, unknown>;

// Sidecar tools whose result may carry a dispatch envelope for the bridge.
export const DISPATCH_TOOLS: ReadonlySet<string> = new Set([
  "extras_close_all_open_detections_on_host",
]);

/** Call one eyas-mcp tool; resolve to its first JSON object, or an error. */
export type CallNative = (
  name: string,
  args: Obj,
  opts?: { timeoutMs?: number },
) => Promise<{ obj: Obj | null; error: string | null }>;

// Batch session + command each wait up to this long inside eyas-mcp, and the
// per-host wait is 5 s shorter. Long scripts (Windows Update) come back
// complete:false with a cloud_request_id that the agent polls.
export const RUN_TIMEOUT_SECONDS = 40;
// The run call can spend a session-open wait plus a command wait, so it gets
// its own client timeout above the default 60 s.
const RUN_CALL_TIMEOUT_MS = (RUN_TIMEOUT_SECONDS * 2 + 20) * 1000;

const NATIVE_PLATFORM: Record<string, string> = { windows: "windows", linux: "linux", macos: "mac", mac: "mac" };
const AID = /^[0-9a-fA-F]{32}$/;

const isObj = (v: unknown): v is Obj => !!v && typeof v === "object" && !Array.isArray(v);
const str = (v: unknown) => (typeof v === "string" ? v : v == null ? "" : String(v));

/** The dispatch envelope a sidecar result carries, or null. */
export function dispatchOf(result: unknown): Obj | null {
  return isObj(result) && isObj(result.dispatch) ? result.dispatch : null;
}

function randomSuffix(): string {
  const bytes = new Uint8Array(6);
  globalThis.crypto.getRandomValues(bytes);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Carry out `result.dispatch`. Returns the result to show the agent in place
 * of the envelope.
 */
export async function runDispatch(
  result: Obj,
  callNative: CallNative,
  newScriptName: () => string = () => `eyas-run-${randomSuffix()}`,
): Promise<Obj> {
  const dispatch = dispatchOf(result);
  if (!dispatch) return result;
  const { dispatch: _drop, ...meta } = result;
  void _drop;

  if (dispatch.kind === "rtr_status") return checkStatus(dispatch, callNative);
  if (dispatch.kind === "close_host_detections") return { ...meta, ...(await closeHostDetections(dispatch, callNative)) };
  if (dispatch.kind === "rtr_script") return { ...meta, ...(await runScript(dispatch, callNative, newScriptName)) };
  return { ok: false, error: `Unknown dispatch kind ${str(dispatch.kind)}.` };
}

async function runScript(dispatch: Obj, callNative: CallNative, newScriptName: () => string): Promise<Obj> {
  const body = dispatch.script_body;
  const platform = NATIVE_PLATFORM[str(dispatch.platform)];
  const deviceIds = Array.isArray(dispatch.device_ids)
    ? dispatch.device_ids.filter((d): d is string => typeof d === "string" && AID.test(d)).map((d) => d.toLowerCase())
    : [];
  if (typeof body !== "string" || !body.trim()) return { ok: false, stage: "render", error: "No script was rendered." };
  if (!platform) return { ok: false, stage: "render", error: `Unsupported platform ${str(dispatch.platform)}.` };
  if (deviceIds.length === 0) return { ok: false, stage: "render", error: "No valid host IDs to run on." };

  const name = newScriptName();
  const created = await callNative("falcon_create_rtr_script", {
    name,
    content: body,
    platform,
    permission_type: "private",
    description: "Eyas one-off run (deleted after dispatch)",
  });
  if (created.error || !created.obj) {
    return { ok: false, stage: "create_script", error: created.error ?? "Upload returned nothing." };
  }
  const scriptId = typeof created.obj.id === "string" ? created.obj.id : null;
  if (!scriptId) {
    // Uploaded, but the id lookup failed: don't run a script we can't delete.
    return {
      ok: false,
      stage: "create_script",
      error: `Uploaded ${name} but couldn't read its id back, so it was not run. Delete it from the custom script library.`,
    };
  }

  let run: { obj: Obj | null; error: string | null };
  let deleteError: string | null = null;
  try {
    run = await callNative(
      "falcon_run_rtr_script_on_hosts",
      { script_name: name, device_ids: deviceIds, timeout_seconds: RUN_TIMEOUT_SECONDS },
      { timeoutMs: RUN_CALL_TIMEOUT_MS },
    );
  } finally {
    // Commands already sent keep running; this only removes the library entry.
    const del = await callNative("falcon_delete_rtr_scripts", { ids: [scriptId] }).catch((e: unknown) => ({
      obj: null,
      error: e instanceof Error ? e.message : String(e),
    }));
    deleteError = del.error;
  }
  // A leftover one-off script is harmless to the hosts but clutters the
  // library, so say so rather than drop it.
  const cleanup = deleteError
    ? { cleanup_warning: `Couldn't delete the one-off script ${name} (${deleteError}). Remove it from the custom script library.` }
    : {};
  if (run.error || !run.obj) {
    return { ok: false, stage: "run_script", error: run.error ?? "The run returned nothing.", ...cleanup };
  }
  return { ...shapeRun(run.obj), ...cleanup };
}

/** Native run result → the sidecar's former run_batch shape. */
export function shapeRun(run: Obj): Obj {
  const results: Obj[] = [];
  for (const r of Array.isArray(run.results) ? run.results : []) {
    if (!isObj(r)) continue;
    const complete = r.complete === true;
    const errors = r.errors;
    const hasErrors = Array.isArray(errors) ? errors.length > 0 : !!errors;
    results.push({
      device_id: str(r.device_id),
      ok: complete && !hasErrors,
      stdout: str(r.stdout ?? (r.output !== undefined ? JSON.stringify(r.output) : "")),
      stderr: str(r.stderr),
      exit_code: null,
      error: hasErrors ? (typeof errors === "string" ? errors : JSON.stringify(errors)) : null,
      cloud_request_id: typeof r.task_id === "string" ? r.task_id : null,
      complete,
    });
  }
  for (const f of Array.isArray(run.failed_hosts) ? run.failed_hosts : []) {
    if (!isObj(f)) continue;
    const errors = f.errors;
    results.push({
      device_id: str(f.device_id),
      ok: false,
      stdout: "",
      stderr: "",
      exit_code: null,
      error: typeof errors === "string" ? errors : JSON.stringify(errors ?? `${str(f.phase) || "run"} failed`),
      cloud_request_id: null,
      // Nothing is running on this host, so there is nothing to poll.
      complete: true,
    });
  }
  const okCount = results.filter((r) => r.ok).length;
  return {
    ok: okCount > 0,
    batch_id: run.batch_id ?? null,
    host_count: results.length,
    ok_count: okCount,
    results,
    ...(typeof run.warning === "string" ? { warning: run.warning } : {}),
  };
}

async function checkStatus(dispatch: Obj, callNative: CallNative): Promise<Obj> {
  const ids = Array.isArray(dispatch.cloud_request_ids)
    ? dispatch.cloud_request_ids.filter((i): i is string => typeof i === "string" && !!i.trim())
    : [];
  if (ids.length === 0) return { ok: false, error: "cloud_request_ids is empty" };
  const res = await callNative("falcon_check_rtr_admin_command_status", { cloud_request_ids: ids });
  if (res.error || !res.obj) return { ok: false, error: res.error ?? "The status check returned nothing." };
  const results = (Array.isArray(res.obj.results) ? res.obj.results : []).filter(isObj).map((r) => ({
    cloud_request_id: str(r.cloud_request_id),
    complete: r.complete === true,
    stdout: str(r.stdout),
    stderr: str(r.stderr),
    exit_code: null,
    errors: Array.isArray(r.errors) ? r.errors : r.errors ? [r.errors] : [],
    ...(typeof r.error === "string" ? { error: r.error } : {}),
  }));
  return {
    ok: true,
    count: results.length,
    complete_count: results.filter((r) => r.complete).length,
    results,
  };
}

// Bulk close on the operator's request ("the host is clean, close everything
// open on it"). IR Phase 4 doesn't use this: it closes only what the
// remediation ledger matched (extras_ir_close_remediated). eyas-mcp closes
// every open detection tied to the host, from any product (NGSIEM correlation
// alerts that name only this host included), in batches.
// The result keeps the sidecar's former shape (scope_count / updated /
// requested / composite_ids) that the IR record, summaries and UI read.
async function closeHostDetections(dispatch: Obj, callNative: CallNative): Promise<Obj> {
  const deviceId = str(dispatch.device_id);
  const resolution = str(dispatch.resolution);
  if (!AID.test(deviceId)) return { ok: false, error: "device_id must be a 32-character host ID." };
  const res = await callNative("falcon_close_host_detections", {
    device_id: deviceId,
    resolution,
    ...(typeof dispatch.comment === "string" && dispatch.comment.trim() ? { comment: dispatch.comment } : {}),
    ...(dispatch.include_multi_host === true ? { include_multi_host: true } : {}),
  });
  const o = res.obj;
  if (res.error || !o) return { ok: false, device_id: deviceId, verdict: resolution, error: res.error ?? "The close returned nothing." };
  const found = typeof o.found === "number" ? o.found : 0;
  const closed = typeof o.closed === "number" ? o.closed : 0;
  return {
    ok: true,
    device_id: deviceId,
    verdict: resolution,
    scope_count: found,
    requested: found,
    updated: closed,
    composite_ids: Array.isArray(o.composite_ids) ? o.composite_ids : [],
    // eyas-mcp ≥ bfc9f50: how each alert was found, and correlation alerts
    // that also name other hosts (left open unless include_multi_host).
    ...(isObj(o.matched_by) ? { matched_by: o.matched_by } : {}),
    ...(isObj(o.skipped_multi_host) ? { skipped_multi_host: o.skipped_multi_host } : {}),
    ...(found === 0 ? { note: "No open detections on this host — nothing to close." } : {}),
    ...(typeof o.warning === "string" ? { warning: o.warning } : {}),
  };
}
