// Ledger entry → detection matcher for extras_ir_close_remediated.
//
// IR Phase 4 walks every open detection on the host and asks "did Phase 2
// actually touch this?" Each remediated[] entry from the agent's structured
// ledger is matched against the detection's evidence (process ids, the
// cmdline corpus across alert / parent / behaviors, hashes, pattern ids). A
// match closes the detection with an audit string naming the ledger entry and
// the field that fired.
//
// Match policy:
// * Generous on cmdline substrings: case-insensitive, slashes normalized,
//   since one path appears with different quoting and casing across
//   alert.cmdline, parent_details.cmdline, behaviors[].cmdline / ioc_value /
//   filepath.
// * Strict on identifiers: pid / sha256 / md5 / pattern_id / WMI filter name
//   must match exactly (a substring would over-close).
// * Host state changes (contain, lift, reboot) are not remediation and never
//   close a detection; only an entry naming the specific artifact acted on.
// * Unknown or "other" kinds never match; they are notes, not actions.
//
// Adding a remediation primitive: add a `kind` branch here, tell the agent to
// emit that ledger entry in the IR playbook's Phase 2
// (lib/eyas-tools/playbooks/ir.ts), and add a test in
// scripts/test-ir-ledger-matcher.mjs.
//
// Pure: no I/O.

type Obj = Record<string, unknown>;

const isObj = (v: unknown): v is Obj => !!v && typeof v === "object" && !Array.isArray(v);
const asList = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
/** Lower-cased string field, "" when absent or not a string. */
const lowerStr = (v: unknown): string => (typeof v === "string" ? v.toLowerCase() : "");
/** Python str() of a scalar id (pid, pattern id). */
const idStr = (v: unknown): string => (typeof v === "boolean" ? (v ? "True" : "False") : String(v));
const isSet = (v: unknown) => v !== null && v !== undefined;
const slashes = (s: string) => s.replace(/\//g, "\\");
const basename = (s: string) => s.slice(s.lastIndexOf("\\") + 1);

// Shortest basename / name eligible for the bounded-token cmdline fallback.
// Short common tokens (cmd.exe, time, run) match huge swaths of the queue and
// would close detections nothing remediated. The matcher prefers to
// under-close: an unmatched detection stays open for review, an over-matched
// one hides a real threat. Exact identifier matches and exact basename
// equality against the alert's own process image are unaffected.
export const BOUNDED_TOKEN_FLOOR = 6;

const escapeRx = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** `needle` appears in `blob` bounded on each side by something that is not a
 *  word character or a dot (path separator, quote, space, comma, paren or the
 *  string edge). `cmd.exe` does not match inside `cmd.exe.bak`, a service
 *  named `time` does not match `runtime`. Inputs are lower-cased and
 *  slash-normalized already. Word characters are Unicode, as in Python. */
export function boundedTokenInBlob(needle: string, blob: string): boolean {
  if (!needle || !blob) return false;
  return new RegExp(`(?<![\\p{L}\\p{N}_.])${escapeRx(needle)}(?![\\p{L}\\p{N}_.])`, "u").test(blob);
}

function normPath(p: unknown): string {
  if (typeof p !== "string" || !p) return "";
  return slashes(p.toLowerCase()).trim().replace(/\\+$/, "");
}

/** Every cmdline-bearing field of an alert as one lower-cased blob. */
export function alertCmdlineCorpus(alert: Obj): string {
  const parts: string[] = [];
  if (typeof alert.cmdline === "string") parts.push(alert.cmdline);
  if (isObj(alert.parent_details) && typeof alert.parent_details.cmdline === "string") {
    parts.push(alert.parent_details.cmdline);
  }
  for (const b of asList(alert.behaviors)) {
    if (!isObj(b)) continue;
    for (const k of ["cmdline", "ioc_value", "filepath", "filename"]) {
      if (typeof b[k] === "string") parts.push(b[k] as string);
    }
  }
  return slashes(parts.join(" ").toLowerCase());
}

/** Basenames of the alert's process-image fields: the files the detection is
 *  about, not strings that merely appear in a command line. */
function alertImageBasenames(alert: Obj): Set<string> {
  const out = new Set<string>();
  const add = (v: unknown) => {
    if (typeof v === "string" && v) {
      const base = basename(slashes(v.toLowerCase()));
      if (base) out.add(base);
    }
  };
  for (const k of ["filename", "filepath", "image_filename", "image_file_name"]) add(alert[k]);
  for (const b of asList(alert.behaviors)) {
    if (isObj(b)) {
      add(b.filename);
      add(b.filepath);
    }
  }
  return out;
}

function alertPids(alert: Obj): Set<string> {
  const pids = new Set<string>();
  if (isSet(alert.process_id)) pids.add(idStr(alert.process_id));
  for (const b of asList(alert.behaviors)) {
    if (!isObj(b)) continue;
    if (isSet(b.process_id)) pids.add(idStr(b.process_id));
    if (isSet(b.target_process_id)) pids.add(idStr(b.target_process_id));
  }
  return pids;
}

const HASH_IOC_TYPES = new Set(["sha256", "hash_sha256", "md5", "hash_md5"]);

function alertHashes(alert: Obj): Set<string> {
  const out = new Set<string>();
  for (const b of asList(alert.behaviors)) {
    if (!isObj(b)) continue;
    for (const k of ["sha256", "md5"]) {
      const v = b[k];
      if (typeof v === "string" && v) out.add(v.toLowerCase());
    }
    if (typeof b.ioc_value === "string" && HASH_IOC_TYPES.has(lowerStr(b.ioc_type))) {
      out.add(b.ioc_value.toLowerCase());
    }
  }
  return out;
}

function alertPatternIds(alert: Obj): Set<string> {
  const out = new Set<string>();
  for (const b of asList(alert.behaviors)) {
    if (isObj(b) && isSet(b.pattern_id)) out.add(idStr(b.pattern_id));
  }
  return out;
}

/** Python `str` of a ledger value interpolated into a reason string. */
const show = (v: unknown) => (v === null || v === undefined ? "None" : idStr(v));

/** `[matched, reason]`; the reason is the audit-trail evidence string. */
export function ledgerEntryMatchesAlert(entry: Obj, alert: Obj): [boolean, string | null] {
  const kind = lowerStr(entry.kind);
  const NO: [boolean, null] = [false, null];

  const cmdlineBlob = alertCmdlineCorpus(alert);
  const pids = alertPids(alert);
  const hashes = alertHashes(alert);
  const patternIds = alertPatternIds(alert);
  const imageBasenames = alertImageBasenames(alert);
  const behaviors = asList(alert.behaviors).filter(isObj);

  if (kind === "process_killed") {
    const pid = entry.pid;
    if (isSet(pid) && pids.has(idStr(pid))) return [true, `process_killed pid=${show(pid)} matches alert pid`];
    // Exact basename equality against the alert's own process image only. No
    // cmdline fallback: a killed common interpreter (cmd.exe, powershell.exe)
    // is mentioned in countless unrelated cmdlines.
    if (typeof entry.image === "string" && entry.image) {
      const base = basename(slashes(entry.image.toLowerCase()));
      if (base && imageBasenames.has(base)) return [true, `process_killed image=${base} matches alert process image`];
    }
    return NO;
  }

  if (kind === "file_quarantined" || kind === "file_deleted") {
    const sha = lowerStr(entry.sha256);
    const md5 = lowerStr(entry.md5);
    if (sha && hashes.has(sha)) return [true, `${kind} sha256=${sha.slice(0, 12)}… matches alert hash`];
    if (md5 && hashes.has(md5)) return [true, `${kind} md5=${md5.slice(0, 12)}… matches alert hash`];
    const path = normPath(entry.path);
    // A full path is specific enough for a plain substring match.
    if (path && cmdlineBlob.includes(path)) return [true, `${kind} path=${show(entry.path)} appears in cmdline`];
    if (path) {
      const base = basename(path);
      if (base && base.length >= BOUNDED_TOKEN_FLOOR && boundedTokenInBlob(base, cmdlineBlob)) {
        return [true, `${kind} filename=${base} appears as a delimited token in cmdline`];
      }
    }
    return NO;
  }

  if (kind === "folder_deleted") {
    const path = normPath(entry.path);
    if (path && cmdlineBlob.includes(path)) return [true, `folder_deleted path=${show(entry.path)} appears in cmdline`];
    return NO;
  }

  if (kind === "registry_reverted") {
    // The full normalized key path as a delimited token, never a bare or
    // reverse substring: "…\Run\EvilApp" must not close a "…\Run\EvilAppData"
    // detection, and a short ioc_value fragment must not match a long path.
    const path = normPath(entry.path);
    if (path && path.length >= BOUNDED_TOKEN_FLOOR) {
      for (const b of behaviors) {
        const iv = slashes(lowerStr(b.ioc_value));
        if (iv && boundedTokenInBlob(path, iv)) {
          return [true, `registry_reverted path=${show(entry.path)} matches behavior.ioc_value`];
        }
      }
      if (boundedTokenInBlob(path, cmdlineBlob)) {
        return [true, `registry_reverted path=${show(entry.path)} appears in cmdline`];
      }
    }
    return NO;
  }

  if (kind === "ifeo_removed") {
    if (typeof entry.image === "string" && entry.image) {
      const base = basename(entry.image.toLowerCase());
      for (const b of behaviors) {
        const iv = lowerStr(b.ioc_value);
        if (iv && (iv.includes("image file execution options") || iv.includes("\\ifeo\\")) && iv.includes(base)) {
          return [true, `ifeo_removed image=${base} matches IFEO behavior.ioc_value`];
        }
      }
    }
    return NO;
  }

  if (kind === "ioa_pattern_excluded") {
    const pid = entry.pattern_id;
    if (isSet(pid) && patternIds.has(idStr(pid))) {
      return [true, `ioa_pattern_excluded pattern_id=${show(pid)} matches behavior.pattern_id`];
    }
    return NO;
  }

  if (kind === "ml_exclusion_added") {
    const sha = lowerStr(entry.sha256);
    if (sha && hashes.has(sha)) return [true, `ml_exclusion_added sha256=${sha.slice(0, 12)}… matches alert hash`];
    const path = normPath(entry.path);
    if (path && cmdlineBlob.includes(path)) return [true, `ml_exclusion_added path=${show(entry.path)} appears in cmdline`];
    return NO;
  }

  if (kind === "ioc_added") {
    const v = typeof entry.value === "string" ? entry.value : "";
    const t = lowerStr(entry.type);
    if (!v) return NO;
    const vlow = v.toLowerCase();
    if ((t === "sha256" || t === "md5") && hashes.has(vlow)) {
      return [true, `ioc_added ${t}=${vlow.slice(0, 12)}… matches alert hash`];
    }
    if (cmdlineBlob.includes(vlow)) return [true, `ioc_added ${t}=${v} appears in cmdline`];
    return NO;
  }

  if (kind === "rat_uninstalled") {
    // Image basename only: the product name ("AnyDesk" in any cmdline
    // mentioning anydesk) over-closed.
    if (typeof entry.image === "string" && entry.image) {
      const base = basename(slashes(entry.image.toLowerCase()));
      if (base && imageBasenames.has(base)) return [true, `rat_uninstalled image=${base} matches alert process image`];
      if (base && base.length >= BOUNDED_TOKEN_FLOOR && boundedTokenInBlob(base, cmdlineBlob)) {
        return [true, `rat_uninstalled image=${base} appears as a delimited token in cmdline`];
      }
    }
    return NO;
  }

  if (kind === "service_removed" || kind === "scheduled_task_removed") {
    const name = entry.service_name || entry.task_name || "";
    if (typeof name === "string" && name.length >= BOUNDED_TOKEN_FLOOR && boundedTokenInBlob(name.toLowerCase(), cmdlineBlob)) {
      return [true, `${kind} name=${name} appears as a delimited token in cmdline`];
    }
    return NO;
  }

  if (kind === "wmi_persistence_removed") {
    // Attacker-generated filter names are random: bounded token, length floor.
    const fname = lowerStr(entry.filter_name);
    if (fname && fname.length >= BOUNDED_TOKEN_FLOOR) {
      for (const b of behaviors) {
        const iv = lowerStr(b.ioc_value);
        if (iv && boundedTokenInBlob(fname, iv)) {
          return [true, `wmi_persistence_removed filter_name=${show(entry.filter_name)} matches behavior.ioc_value`];
        }
      }
      if (boundedTokenInBlob(fname, cmdlineBlob)) {
        return [true, `wmi_persistence_removed filter_name=${show(entry.filter_name)} appears in cmdline`];
      }
    }
    return NO;
  }

  // host_contained / host_lifted / host_rebooted, "other" and unknown kinds.
  return NO;
}
