// Operator-facing humanizer for chat hand-offs.
//
// Action buttons (and the markdown `[label](/?primer=…)` links the agent emits
// inside responses) hand chat a precise INSTRUCTION string — the agent's prompt,
// packed with tool names, ids, and composite_ids the agent needs but no operator
// should have to read. This module is the single place that turns any such
// instruction into a plain-English `PrimerAction`: a clean title + a one-line
// "what this does and why", with the raw instruction preserved for transparency.
//
// The instruction is NEVER rewritten — only described — so the server-side IR
// detection (and every other agent contract) keeps working unchanged. Because
// the description is derived from the instruction text, it also works for
// resumed conversations and for the agent's own markdown links, with no extra
// data to thread through.
//
// Keep this the ONLY home for hand-off copy: no tool names, file paths, env
// vars, or implementation jargon in any title/subtitle/description here.

export type PrimerKind =
  | "ir"
  | "triage"
  | "reconstruct"
  | "tune"
  | "intel"
  | "patch"
  | "case"
  | "provision"
  | "workflow"
  | "ask";

export interface PrimerAction {
  kind: PrimerKind;
  /** Plain-English action title. Shown in the card header and chat bubble. */
  title: string;
  /** Optional one-line context (host / rule / user). */
  subtitle?: string;
  /** One or two sentences: what this does and why. No jargon. */
  description: string;
  /** The precise instruction sent to the agent — preserved verbatim. */
  instruction: string;
  /** True when a known hand-off template matched (so the UI can humanize). */
  matched: boolean;
}

type Matcher = {
  test: RegExp;
  build: (m: RegExpMatchArray, raw: string) => Omit<PrimerAction, "instruction" | "matched">;
};

const plural = (n: number | string, word: string) =>
  `${n} ${word}${String(n) === "1" ? "" : "s"}`;

// Most specific patterns first; the first match wins.
const MATCHERS: Matcher[] = [
  {
    // Identity IR must precede endpoint IR (both start "Run the agentic … IR").
    test: /^Run the agentic identity IR workflow on user `?([^`\n]+?)`?\./,
    build: (m) => ({
      kind: "ir",
      title: `Run guided identity incident response for ${m[1]}`,
      subtitle: `User ${m[1]}`,
      description:
        "Investigates the account and runs incident response on every machine the user recently signed into. Each step waits for your approval before it runs.",
    }),
  },
  {
    test: /^Run the agentic IR workflow on host `?([^`\n]+?)`?\s*\(AID/,
    build: (m) => ({
      kind: "ir",
      title: `Run guided incident response on ${m[1]}`,
      subtitle: `Host ${m[1]}`,
      description:
        "Contains the host, hunts for persistence, and cleans confirmed threats. Each step waits for your approval before it runs.",
    }),
  },
  {
    test: /^Triage (\d+) open detections on host `?([^`\n]+?)`?[\s:.]/,
    build: (m) => ({
      kind: "triage",
      title: `Triage ${plural(m[1], "open detection")} on ${m[2]}`,
      subtitle: `Host ${m[2]}`,
      description:
        "Reviews each open detection, gathers context from across Falcon, and recommends a verdict and next steps.",
    }),
  },
  {
    // IOC precheck on a file hash pulled from a detection (the "Triage hash"
    // button). Host clause is present only when the detection carries a
    // hostname. Keep the raw hash / composite_id out of the title — they live
    // behind the preserved-instruction disclosure.
    test: /^Triage hash `?[0-9a-fA-F]+`? \(type \w+\)(?: from detection .+? on host `([^`]+)`)?/,
    build: (m) => ({
      kind: "triage",
      title: m[1]
        ? `Check a file hash against threat intelligence on ${m[1]}`
        : "Check a file hash against threat intelligence",
      subtitle: m[1] ? `Host ${m[1]}` : undefined,
      description:
        "Checks whether this file hash is already known to Falcon Intelligence or your custom indicator list, and only proposes adding it if both miss — for your approval.",
    }),
  },
  {
    test: /^Triage detection\b/,
    build: (_m, raw) => {
      const host = raw.match(/ on host `([^`]+)`/);
      return {
        kind: "triage",
        title: host ? `Triage a detection on ${host[1]}` : "Triage this detection",
        subtitle: host ? `Host ${host[1]}` : undefined,
        description:
          "Reviews the detection, gathers context from across Falcon, and recommends a verdict and next steps.",
      };
    },
  },
  {
    test: /^Remediate detection on host ([^\s(]+)/,
    build: (m) => ({
      kind: "triage",
      title: `Remediate a detection on ${m[1]}`,
      subtitle: `Host ${m[1]}`,
      description:
        "Runs the recommended cleanup or containment on the host. You preview it first and approve before anything executes.",
    }),
  },
  {
    test: /^Reconstruct the cross-host campaign\b/,
    build: (_m, raw) => {
      const hosts = raw.match(/Affected hosts:\s*([^.]+?)\./);
      const count = hosts ? hosts[1].split(",").filter((s) => s.trim()).length : 0;
      return {
        kind: "reconstruct",
        title: count
          ? `Reconstruct the campaign across ${plural(count, "host")}`
          : "Reconstruct this campaign",
        description:
          "Stitches the related detections across hosts into one timeline and attack narrative.",
      };
    },
  },
  {
    test: /^Draft a tuning recommendation for rule `?([^`\n]+?)`?\./,
    build: (m) => ({
      kind: "tune",
      title: `Draft a tuning recommendation for ${m[1]}`,
      subtitle: `Rule ${m[1]}`,
      description:
        "Reviews the false-positive evidence and proposes a precise exclusion to cut the noise — for your approval.",
    }),
  },
  {
    // Home dashboard "prevention posture gap" hand-off. Count-only; no ids in
    // the instruction, so the humanized copy needs no host/rule clause.
    test: /^Review the (\d+) detect-only prevention (?:policy|policies) and recommend/,
    build: (m) => ({
      kind: "tune",
      title: `Review ${m[1]} detect-only prevention ${m[1] === "1" ? "policy" : "policies"}`,
      description:
        "Looks at which prevention policies are set to detect-only and recommends which should move to blocking — for your approval.",
    }),
  },
  {
    test: /^Investigate the active intel hit on indicator (?:`([^`]+)`|([^\s(]+))/,
    build: (m) => ({
      kind: "intel",
      title: `Investigate intel hit on ${m[1] ?? m[2]}`,
      description:
        "Checks this indicator against Falcon Intelligence and correlates it with recent activity in your tenant.",
    }),
  },
  {
    test: /^Look up indicator (?:`([^`]+)`|([^\s(]+))/,
    build: (m) => ({
      kind: "intel",
      title: `Look up ${m[1] ?? m[2]} in Falcon Intelligence`,
      description:
        "Pulls what Falcon Intelligence knows about this indicator — associated actors, malware families, and confidence.",
    }),
  },
  {
    test: /^Tell me about adversary (?:`([^`]+)`|([^\s(]+))/,
    build: (m) => ({
      kind: "intel",
      title: `Profile adversary ${m[1] ?? m[2]}`,
      description:
        "Pulls the threat actor's profile and any activity attributed to them in your tenant.",
    }),
  },
  {
    // The host count may carry a " (truncated from N)" clause when the
    // affected fleet exceeds the embedded-id cap — absorb it so the matcher
    // doesn't fall through to raw text (which would leak the AID array).
    test: /^Patch (.+?) via the curated RTR script library on (\d+)(?: \(truncated from \d+\))? host/,
    build: (m) => ({
      kind: "patch",
      title: `Patch ${m[1]} on ${plural(m[2], "host")}`,
      description:
        "Runs the curated update on the affected hosts. You preview the plan and approve before anything executes.",
    }),
  },
  {
    // Generic Windows installer — the app has no curated update script, so the
    // operator supplied a vendor download link. Absorb the optional "(truncated
    // from N)" host clause; keep the URL / AID array / hash out of the humanized
    // copy (they live behind the preserved-instruction disclosure).
    test: /^Install (.+?) via the generic Windows installer from \S+ on (\d+)(?: \(truncated from \d+\))? host/,
    build: (m) => ({
      kind: "patch",
      title: `Install ${m[1]} on ${plural(m[2], "host")}`,
      description:
        "Downloads the app from the vendor link you provided and installs it on the affected hosts. You preview the plan and approve before anything runs.",
    }),
  },
  {
    // Save a vendor download link as a reusable install source. No host action.
    test: /^Save a reusable patch profile for (.+?) from vendor URL /,
    build: (m) => ({
      kind: "provision",
      title: `Save a reusable patch source for ${m[1]}`,
      description:
        "Saves the vendor download link so you can reinstall or update this app later in one step. Nothing runs on any host now.",
    }),
  },
  {
    test: /^Help me triage (CVE-[0-9-]+)/i,
    build: (m) => ({
      kind: "triage",
      title: `Triage ${m[1].toUpperCase()}`,
      description:
        "Checks exploit status, fix availability, and whether affected hosts are already showing related detections.",
    }),
  },
  {
    test: /^Triage Falcon case `?([^`\n]+?)`?\s*\(/,
    build: (m) => ({
      kind: "case",
      title: `Triage Falcon case ${m[1]}`,
      description:
        "Loads the case and works through its evidence toward a verdict and recommended next steps.",
    }),
  },
  {
    test: /^Investigate Fusion workflow execution `?[^`\n]+?`? from `?([^`\n]+?)`?\s*\(/,
    build: (m) => ({
      kind: "workflow",
      title: `Investigate the failed automation "${m[1]}"`,
      description:
        "Retrieves the automation run's outputs and explains the root cause of the failure.",
    }),
  },
  {
    test: /^Provision Data Protection coverage\b/,
    build: () => ({
      kind: "provision",
      title: "Set up Data Protection coverage",
      description:
        "Walks you through protecting sensitive data — it asks what to protect and on which systems first, then provisions monitoring.",
    }),
  },
  {
    test: /^Create the IR quarantine host group\b/,
    build: () => ({
      kind: "provision",
      title: "Set up the incident-response quarantine group",
      description:
        "Creates the host group that incident response moves machines into, and saves it to this environment.",
    }),
  },
  {
    test: /^Provision the IR quarantine prevention policies\b/,
    build: () => ({
      kind: "provision",
      title: "Provision incident-response containment policies",
      description:
        "Attaches aggressive prevention policies to the quarantine group so contained hosts are fully locked down.",
    }),
  },
  {
    test: /^Create the Shadow-AI Banned host group\b/,
    build: () => ({
      kind: "provision",
      title: "Set up the Shadow-AI blocked host group",
      description:
        "Creates the host group used to block unsanctioned AI tools, and saves it to this environment.",
    }),
  },
  {
    test: /^Provision the Shadow-AI Banned prevention policies\b/,
    build: () => ({
      kind: "provision",
      title: "Provision Shadow-AI blocking policies",
      description:
        "Attaches prevention policies and the AI-blocking rules to the blocked host group.",
    }),
  },
  {
    test: /^Refresh the Shadow-AI rule corpus\b/,
    build: () => ({
      kind: "provision",
      title: "Refresh the Shadow-AI blocking rules",
      description:
        "Adds any missing AI-blocking rules to the policy. Rules already in place are left untouched.",
    }),
  },
  {
    test: /^Run the agentic Shadow-AI ban-and-clean workflow on host `?([^`\n]+?)`?\s*\(AID/,
    build: (m) => ({
      kind: "workflow",
      title: `Ban and clean unsanctioned AI tools on ${m[1]}`,
      subtitle: `Host ${m[1]}`,
      description:
        "Moves the host into the blocked group, uninstalls unsanctioned AI tools, and adds detect-only indicators for their service endpoints. Each step waits for your approval before it runs.",
    }),
  },
  {
    test: /^Build a Shadow-AI remediation plan for host `?([^`\n]+?)`?\s*\(AID/,
    build: (m) => ({
      kind: "ask",
      title: `Plan Shadow-AI remediation for ${m[1]}`,
      subtitle: `Host ${m[1]}`,
      description:
        "Reviews the unsanctioned AI tools, network activity, and local model servers found on the host, then recommends how to remediate.",
    }),
  },
  {
    test: /^Tell me about host (?:`([^`]+)`|([^\s(]+))/,
    build: (m) => {
      const host = m[1] ?? m[2];
      return {
        kind: "ask",
        title: `Ask about host ${host}`,
        subtitle: `Host ${host}`,
        description:
          "Summarizes the host's recent detections, open vulnerabilities, and anything currently concerning.",
      };
    },
  },
];

/** First sentence (or a clipped prefix) of an unrecognized instruction. */
function firstSentence(text: string, max = 96): string {
  const oneLine = text.replace(/\s+/g, " ").trim();
  const stop = oneLine.search(/[.!?](\s|$)/);
  const candidate = stop > 0 && stop < max ? oneLine.slice(0, stop + 1) : oneLine;
  return candidate.length > max ? `${candidate.slice(0, max - 1).trimEnd()}…` : candidate;
}

/**
 * Describe a chat hand-off instruction in operator language. Always returns a
 * usable PrimerAction; `matched` is false for free-form text that no template
 * recognized (callers render those verbatim instead of as a summary + details).
 */
export function describePrimer(instruction: string): PrimerAction {
  const raw = instruction.trim();
  for (const matcher of MATCHERS) {
    const m = raw.match(matcher.test);
    if (m) {
      return { ...matcher.build(m, raw), instruction: raw, matched: true };
    }
  }
  return {
    kind: "ask",
    title: firstSentence(raw),
    description: "Sends this request to the agent.",
    instruction: raw,
    matched: false,
  };
}
