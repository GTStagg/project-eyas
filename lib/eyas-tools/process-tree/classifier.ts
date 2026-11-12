// Delivery-vector classifier for process-tree ancestry chains.
//
// Pure: given an ordered ancestry list (pivot at index 0, walking up toward
// the root) it returns the {kind, confidence, rationale, ...} verdict that
// drives the IR playbook's Phase 0 decisions. It turns "process X fired a
// detection" into "this attack arrived via Y", so the Phase 2 response covers
// the delivery channel (pull the email, audit the browser, isolate the
// lateral source) and not just the on-host cleanup.
//
// eyas-mcp's falcon_get_process_tree carries a generic heuristic of its own;
// this is Eyas's curated vocabulary (user_executed_dropper, phishing_doc,
// lateral_winrm, c2_agent, …) that the IR playbook branches on, plus the
// per-node verdicts the detection drawer renders.
//
// Walking rules:
// - Anchors are images that explain how the attack started (Outlook, Chrome,
//   WINWORD, services.exe, wsmprovhost.exe, ...).
// - Walk pivot → root and take the most specific anchor: Office AND a mail
//   client in the chain is a phishing doc, not a direct phishing email.
// - Confidence is "high" for an explicit anchor found without widening the
//   window, "medium" when a parent came from the wider lookup, "low" when
//   only a LOLBin or an unknown ancestor fits.
//
// Per-node verdicts (UI only, they drive no logic): initial-access-anchor,
// office-with-doc, lolbin, c2-agent, signed-system, unknown.
//
// Ported from the sidecar's process_tree/classifier.py; tested in
// scripts/test-process-tree.mjs.

export type TreeNode = Record<string, unknown>;

export const MAIL_CLIENTS = new Set(["outlook.exe", "olk.exe", "hxoutlook.exe", "thunderbird.exe", "lync.exe"]);

export const OFFICE_APPS = new Set([
  "winword.exe",
  "excel.exe",
  "powerpnt.exe",
  "msaccess.exe",
  "mspub.exe",
  "visio.exe",
  "onenote.exe",
  "outlook.exe", // spawn-from-mail-attachment edge
]);

export const BROWSERS = new Set([
  "chrome.exe",
  "msedge.exe",
  "iexplore.exe",
  "firefox.exe",
  "brave.exe",
  "opera.exe",
  "vivaldi.exe",
  "safari.exe",
]);

export const ARCHIVE_TOOLS = new Set(["7zfm.exe", "7zg.exe", "winrar.exe", "rar.exe", "bandizip.exe", "peazip.exe"]);

export const LOLBINS = new Set([
  "cmd.exe",
  "powershell.exe",
  "powershell_ise.exe",
  "pwsh.exe",
  "wscript.exe",
  "cscript.exe",
  "mshta.exe",
  "regsvr32.exe",
  "rundll32.exe",
  "msiexec.exe",
  "installutil.exe",
  "regasm.exe",
  "regsvcs.exe",
  "msbuild.exe",
]);

// Interpreter hosts that often run C2 agents (sliver, havoc, mythic, custom
// python implants). The image alone doesn't classify: the command line must
// also match C2_AGENT_CMDLINE_RX, so build scripts and notebooks don't.
export const C2_AGENT_HOSTS = new Set([
  "python.exe",
  "pythonw.exe",
  "python3.exe",
  "python3.12.exe",
  "py.exe",
  "node.exe",
  "ruby.exe",
  "perl.exe",
]);

// Command-line shapes of an interpreter hosting a remote-control beacon:
// explicit C2 server URLs, beacon/agent script names, listener ports, common
// C2 framework arguments.
const C2_AGENT_CMDLINE_RX = new RegExp(
  [
    String.raw`--server\s+https?://`, // `--server http://10.x.x.x:4444`
    String.raw`-c2\s`, // `-c2 host:port` (havoc, brc4)
    String.raw`--c2-?(server|host|url)\s`,
    String.raw`--listener\s`,
    String.raw`--beacon[=\s]`,
    String.raw`\\agent[\w-]*\.py\b`,
    String.raw`\\beacon[\w-]*\.py\b`,
    String.raw`\\implant[\w-]*\.py\b`,
    String.raw`\\sliver[\w-]*\.(py|exe)\b`,
    String.raw`\\(mythic|havoc|brc4|cobalt)`,
    String.raw`https?://[\w.\-]+:\d{4,5}\b`, // bare `http://host:4444`
  ].join("|"),
  "i",
);

export const SYSTEM_HOSTS = new Set([
  "services.exe",
  "svchost.exe",
  "winlogon.exe",
  "userinit.exe",
  "lsass.exe",
  "csrss.exe",
  "smss.exe",
  "wininit.exe",
  "explorer.exe",
]);

export const LATERAL_HOSTS = new Set(["wsmprovhost.exe", "psexesvc.exe", "paexec.exe", "remcomsvc.exe"]);

export const SCHED_HOSTS = new Set(["taskhostw.exe", "taskhost.exe", "schtasks.exe"]);

export const WMI_HOSTS = new Set(["wmiprvse.exe", "scrcons.exe"]);

// Email-attachment temp paths: an Office process opening a document from one
// of these opened an email attachment. Matched against the lowercased cmdline.
const EMAIL_TEMP_FRAGMENTS = [
  "\\inetcache\\content.outlook\\",
  "\\temporary internet files\\content.outlook",
  "\\appdata\\local\\microsoft\\olk\\",
  "\\appdata\\roaming\\microsoft\\outlook\\",
];

// User download / staging paths, for browser drive-by and user-executed
// dropper.
const USER_DROP_FRAGMENTS = ["\\downloads\\", "\\desktop\\", "\\appdata\\local\\temp\\", "\\users\\public\\"];

const str = (v: unknown): string => (typeof v === "string" ? v : "");

/** Lowercased basename of an image path (either slash). */
export function basename(image: unknown): string {
  const s = str(image);
  if (!s) return "";
  const parts = s.split(/[\\/]/);
  return parts[parts.length - 1].toLowerCase();
}

/** Index of the first node (closest to the pivot) whose image is in `set`. */
function has(images: string[], set: Set<string>): number | null {
  const i = images.findIndex((img) => set.has(img));
  return i < 0 ? null : i;
}

/** An interpreter whose cmdline matches a C2-beacon pattern: the runtime is
 *  legitimate, the script it runs is the implant. */
function isC2Agent(image: unknown, cmdline: unknown): boolean {
  if (!C2_AGENT_HOSTS.has(basename(image))) return false;
  return C2_AGENT_CMDLINE_RX.test(str(cmdline));
}

function nodeVerdict(image: unknown, cmdline: unknown): string {
  const img = basename(image);
  const cmd = str(cmdline).toLowerCase();
  if (isC2Agent(image, cmdline)) return "c2-agent";
  if (OFFICE_APPS.has(img) && EMAIL_TEMP_FRAGMENTS.some((p) => cmd.includes(p))) return "office-with-doc";
  if (OFFICE_APPS.has(img) && /\.(docm?|xlsm?|xlsb|pptm?|ppam?|dotm|xlam|rtf)\b/.test(cmd)) return "office-with-doc";
  if (LOLBINS.has(img)) return "lolbin";
  if (MAIL_CLIENTS.has(img) || BROWSERS.has(img) || ARCHIVE_TOOLS.has(img)) return "initial-access-anchor";
  if (SYSTEM_HOSTS.has(img)) return "signed-system";
  if (LATERAL_HOSTS.has(img)) return "initial-access-anchor";
  if (SCHED_HOSTS.has(img)) return "signed-system";
  if (WMI_HOSTS.has(img)) return "signed-system";
  return "unknown";
}

/** Add a `verdict` to every node that has none (mutates). The classifier then
 *  marks its matched anchor initial-access-anchor. */
export function annotateNodeVerdicts(ancestry: TreeNode[]): void {
  for (const node of ancestry) {
    if (!("verdict" in node)) node.verdict = nodeVerdict(node.image ?? "", node.cmdline ?? "");
  }
}

const DOC_PATH_RX = /['"]?([A-Za-z]:\\[^'"<>|]+?\.(?:docm?|xlsm?|xlsb|pptm?|ppam?|dotm|xlam|rtf|pdf))['"]?/i;

/** The first plausible Office-document path in an Office cmdline, or null. */
function extractDocPath(cmdline: string): string | null {
  if (!cmdline) return null;
  const m = DOC_PATH_RX.exec(cmdline);
  return m ? m[1] : null;
}

/** The first image path (preferred) or cmdline in the chain that mentions a
 *  user-drop fragment. */
function findDropPath(ancestry: TreeNode[], fragments: string[]): string | null {
  for (const node of ancestry) {
    const img = str(node.image).toLowerCase();
    for (const frag of fragments) {
      if (img.includes(frag)) return (node.image as string | null) ?? null;
    }
    const cmd = str(node.cmdline).toLowerCase();
    for (const frag of fragments) {
      if (cmd.includes(frag)) {
        const m = /[A-Za-z]:\\[^\s'"<>|]+/.exec(str(node.cmdline));
        return m ? m[0] : frag;
      }
    }
  }
  return null;
}

const upper = (image: unknown) => basename(image).toUpperCase();

/**
 * Walk the ancestry chain (pivot first) and return the delivery-vector
 * verdict. `windowWidened` (a parent came from outside the window) demotes a
 * high confidence to medium. Marks the matched anchor node
 * initial-access-anchor.
 */
export function classifyDeliveryVector(
  ancestry: TreeNode[],
  { windowWidened = false }: { windowWidened?: boolean } = {},
): Record<string, unknown> {
  if (ancestry.length === 0) {
    return { kind: "unknown", confidence: "low", rationale: "No ancestry data available for the pivot process." };
  }
  const images = ancestry.map((n) => basename(n.image));
  const node = (i: number) => ancestry[i];

  const emit = (
    kind: string,
    confidence: string,
    rationale: string,
    anchorIdx: number | null = null,
    weaponized: string | null = null,
  ): Record<string, unknown> => {
    const out: Record<string, unknown> = { kind, confidence, rationale };
    if (anchorIdx !== null && anchorIdx >= 0 && anchorIdx < ancestry.length) {
      const anchor = node(anchorIdx);
      out.initial_access_pid = anchor.pid ?? null;
      out.initial_access_image = anchor.image ?? null;
      ancestry[anchorIdx].verdict = "initial-access-anchor";
    }
    if (weaponized) out.weaponized_artifact = weaponized;
    if (windowWidened && confidence === "high") out.confidence = "medium";
    return out;
  };

  // Phishing doc: Office in the chain, optionally rooted in a mail client.
  const officeIdx = has(images, OFFICE_APPS);
  const mailIdx = has(images, MAIL_CLIENTS);
  if (officeIdx !== null) {
    const office = node(officeIdx);
    const officeCmd = str(office.cmdline).toLowerCase();
    const weaponized = extractDocPath(str(office.cmdline));
    const isEmailTemp = EMAIL_TEMP_FRAGMENTS.some((p) => officeCmd.includes(p));
    if (mailIdx !== null && mailIdx > officeIdx) {
      return emit(
        "phishing_doc",
        "high",
        `${upper(node(mailIdx).image)} → ${upper(office.image)} opened ${weaponized || "a document"} before child process spawn`,
        mailIdx,
        weaponized,
      );
    }
    if (isEmailTemp) {
      return emit(
        "phishing_doc",
        "high",
        `${upper(office.image)} opened ${weaponized || "a document"} from an email-attachment temp path`,
        officeIdx,
        weaponized,
      );
    }
    // Office without a mail-client ancestor or email temp path: the channel
    // is unclear (share, USB, a saved doc).
    return emit(
      "malicious_document_lateral",
      "medium",
      `${upper(office.image)} spawned malicious child chain from ${weaponized || "a document"}; no mail-client ancestor`,
      officeIdx,
      weaponized,
    );
  }

  // Direct phishing email: mail client → pivot without Office.
  if (mailIdx !== null) {
    return emit(
      "phishing_email_direct",
      "high",
      `${upper(node(mailIdx).image)} spawned the malicious chain directly (likely an executable/script attachment)`,
      mailIdx,
    );
  }

  // Browser drive-by: only with a Downloads/Temp drop path; otherwise the
  // browser is likely a sibling in the chain.
  const browserIdx = has(images, BROWSERS);
  if (browserIdx !== null) {
    const drop = findDropPath(ancestry, USER_DROP_FRAGMENTS);
    if (drop) {
      return emit(
        "browser_drive_by",
        "medium",
        `${upper(node(browserIdx).image)} ancestry with malicious child executing from ${drop}`,
        browserIdx,
        drop,
      );
    }
    return emit(
      "browser_drive_by",
      "low",
      `${upper(node(browserIdx).image)} in ancestry but no Downloads/Temp drop path identified`,
      browserIdx,
    );
  }

  // Archive extraction (the user opened a zip).
  const archiveIdx = has(images, ARCHIVE_TOOLS);
  if (archiveIdx !== null) {
    return emit(
      "archive_extraction",
      "medium",
      `${upper(node(archiveIdx).image)} extracted and the resulting payload spawned the malicious chain`,
      archiveIdx,
    );
  }

  // Lateral movement (WinRM, PsExec).
  const lateralIdx = has(images, LATERAL_HOSTS);
  if (lateralIdx !== null) {
    const img = basename(node(lateralIdx).image);
    if (img === "wsmprovhost.exe") {
      return emit(
        "lateral_winrm",
        "high",
        "WinRM remoting target host process is a direct ancestor — another tenant host invoked PowerShell remoting against this AID",
        lateralIdx,
      );
    }
    return emit(
      "lateral_psexec",
      "high",
      `${img.toUpperCase()} (PsExec-class service) is a direct ancestor — another host invoked SMB-based lateral execution`,
      lateralIdx,
    );
  }

  // Scheduled-task / WMI persistence anchors.
  const schedIdx = has(images, SCHED_HOSTS);
  if (schedIdx !== null && schedIdx >= 1) {
    return emit(
      "scheduled_task_persistence",
      "medium",
      "Scheduled-task host is a direct ancestor — payload was launched by a previously-installed task (persistence trigger)",
      schedIdx,
    );
  }
  const wmiIdx = has(images, WMI_HOSTS);
  if (wmiIdx !== null) {
    return emit(
      "wmi_persistence",
      "medium",
      "WMI provider host is a direct ancestor — payload was launched by a previously-installed __EventConsumer (T1546.003)",
      wmiIdx,
    );
  }

  // Explorer + a drop path: the user double-clicked something they downloaded.
  const explorerIdx = images.indexOf("explorer.exe");
  if (explorerIdx >= 0) {
    const drop = findDropPath(ancestry, USER_DROP_FRAGMENTS);
    if (drop) {
      return emit(
        "user_executed_dropper",
        "medium",
        `explorer.exe spawned the chain from ${drop} — user likely double-clicked an executable in a download/staging path`,
        explorerIdx,
        drop,
      );
    }
  }

  // An interpreter hosting an implant. After the mail / Office / browser
  // anchors (Outlook at the root is still phishing) but before the LOLBin /
  // service fallbacks.
  const c2Idx = ancestry.findIndex((n) => isC2Agent(n.image ?? "", n.cmdline ?? ""));
  if (c2Idx >= 0) {
    const c2 = node(c2Idx);
    const m = /https?:\/\/[\w.\-]+(?::\d+)?(?:\/\S*)?/.exec(str(c2.cmdline));
    const url = m ? m[0] : null;
    return emit(
      "c2_agent",
      "high",
      `${basename(c2.image)} hosting an implant` +
        (url ? ` beaconing to ${url}` : "") +
        " — the interpreter runtime is legitimate, the script it's running is the malicious payload (T1059)",
      c2Idx,
      url,
    );
  }

  // The chain tops out at a LOLBin.
  const lolbinIdx = has(images, LOLBINS);
  if (lolbinIdx !== null && lolbinIdx === ancestry.length - 1) {
    return emit(
      "lolbin_initial",
      "low",
      `Chain terminates at ${upper(node(lolbinIdx).image)} with no upstream context (mail/browser parent may have aged out of the window)`,
      lolbinIdx,
    );
  }

  // Service-spawned binary.
  const svcIdx = images.indexOf("services.exe");
  if (svcIdx >= 1) {
    return emit(
      "malicious_service",
      "medium",
      "services.exe is a direct ancestor — payload runs under a Windows service the attacker installed for persistence",
      svcIdx,
    );
  }

  return {
    kind: "unknown",
    confidence: "low",
    rationale:
      "Ancestry chain has no recognized initial-access anchor (mail/browser/Office/archive/lateral/persistence). " +
      "Sensor data may have aged out of the search window, or the chain is rooted in a context not yet covered by the classifier.",
  };
}
