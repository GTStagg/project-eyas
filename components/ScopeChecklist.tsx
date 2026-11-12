"use client";

import { useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";

// Authoritative mapping: Falcon console scope row → which surfaces in this
// app the scope unlocks. The console-name column should match what shows
// up in Falcon → Support → API Clients and Keys; the read/write column
// reflects what the underlying FalconPy methods actually need (write
// implies r/w, read is enough for read-only surfaces).
//
// Keep this list as the SINGLE SOURCE OF TRUTH for "what scopes does this
// app need." Cross-checked against `CLAUDE.md` "Falcon scope" section and
// the live probe (`node scripts/falcon-scope-probe.mjs --all`).

type Tier = "core" | "discover" | "cases" | "falcon011" | "intel" | "identity" | "aidr" | "cloud" | "optional";

type ScopeRow = {
  consoleName: string;
  read: boolean;
  write: boolean;
  unlocks: string;
};

const SCOPES: Record<Tier, ScopeRow[]> = {
  core: [
    { consoleName: "Alerts", read: true, write: true, unlocks: "/queue Triage Brief; agent verdict updates (true_positive / false_positive / closed)" },
    { consoleName: "Detections", read: true, write: false, unlocks: "Legacy detections API (CrowdStrike retiring; Alerts is the canonical surface)" },
    { consoleName: "Hosts", read: true, write: true, unlocks: "/hosts; queue containment overlay; IR Phase 1 host containment" },
    { consoleName: "Host Group", read: true, write: true, unlocks: "IR Phase 1 quarantine + Phase 4 restoration" },
    { consoleName: "Real Time Response", read: true, write: true, unlocks: "Cleanup catalog session lifecycle; falconscript catalog" },
    { consoleName: "Real Time Response (Admin)", read: true, write: true, unlocks: "Patching catalog (script upload + admin commands); IR Phase 2 cleanup execution" },
    { consoleName: "Vulnerabilities", read: true, write: false, unlocks: "/vulnerabilities; patch-plan agent" },
    { consoleName: "Indicators (Custom)", read: true, write: true, unlocks: "Custom IOC management (allow/block hashes/domains); chat IOC workflow" },
    { consoleName: "Custom IOA Rules", read: true, write: true, unlocks: "Custom IOA rule management" },
    { consoleName: "Firewall Management", read: true, write: true, unlocks: "Firewall rule group management" },
    { consoleName: "Sensor Usage", read: true, write: false, unlocks: "Cost / sensor consumption context" },
    { consoleName: "Scheduled Reports", read: true, write: false, unlocks: "Scheduled jobs (patch digest, daily briefing); save-as-report from /ngsiem" },
    { consoleName: "NGSIEM (Investigate)", read: true, write: false, unlocks: "/ngsiem natural-language → CQL surface" },
    { consoleName: "NGSIEM Data Connections API", read: true, write: false, unlocks: "/ngsiem pipeline-health strip · connector inventory" },
    { consoleName: "NGSIEM Parsers", read: true, write: false, unlocks: "/ngsiem pipeline-health strip · parser inventory" },
    { consoleName: "NGSIEM Lookup Files", read: true, write: false, unlocks: "/ngsiem pipeline-health strip · lookup-file inventory" },
  ],
  // Falcon Discover asset/account/application inventory — backs the /discover
  // surface. The 2026-06-08 live probe (scripts/falcon-scope-probe.mjs)
  // confirmed all four Discover read endpoints (applications / hosts / accounts
  // / logins) return 200 on the SE tenant, so the capability is real. The
  // CONSOLE LABEL is edition-dependent and uncertain — on this tenant it is
  // believed to be "Assets" (there is no "Exposure Management" row); older
  // editions label it "Falcon Discover". If the row below doesn't match your
  // console's API-scope list, grant the closest asset-inventory equivalent.
  discover: [
    { consoleName: "Assets (Falcon Discover)", read: true, write: false, unlocks: "/discover inventory — managed + unmanaged endpoints, installed applications, local / AD accounts and logins" },
  ],
  // New in falcon-mcp 0.10.0 (replaced the removed Incidents module).
  // Scope names per the upstream cases module's documented requirements:
  // Cases:read, Cases:write, Case Templates:read. /cases ships staged —
  // without these the nav item hides and the page shows a scope-pending
  // banner — so granting them is the single switch that lights it up.
  cases: [
    { consoleName: "Cases", read: true, write: true, unlocks: "/cases dashboard (read); agent case workflow — create / update / attach alert+event evidence / tag (write, approval-gated)" },
    { consoleName: "Case Templates", read: true, write: false, unlocks: "Template-driven case creation (falcon_list_case_templates → create_case with a template)" },
  ],
  // New in falcon-mcp 0.11.0 (quarantine, correlationrules, dataprotection
  // modules). Each backs a staged decision-doc surface — without the scope the
  // nav item hides and the page shows a scope-pending banner. Writes on
  // quarantine + correlation are approval-gated in chat.
  falcon011: [
    { consoleName: "Quarantine", read: true, write: true, unlocks: "/quarantine review (read); release / unrelease / delete quarantined files (write, approval-gated in chat)" },
    { consoleName: "Correlation Rules", read: true, write: true, unlocks: "/correlation rule-health review (read); create / update / delete correlation rules (write, approval-gated in chat). Tenant also exposes a separate Correlation Rules Admin scope." },
    { consoleName: "Data Protection", read: true, write: true, unlocks: "/data-protection exposure posture (read); create content patterns / classifications / policies (write, approval-gated in chat)" },
  ],
  intel: [
    { consoleName: "Falcon Intelligence: Actors", read: true, write: false, unlocks: "/intel actor catalog + per-actor detail" },
    { consoleName: "Falcon Intelligence: Indicators", read: true, write: false, unlocks: "Hash/IP/domain reputation precheck (used before falcon_add_ioc)" },
    { consoleName: "Monitoring Rules (Falcon Intelligence Recon)", read: true, write: false, unlocks: "/recon dark web / breach / paste / Telegram exposure" },
    { consoleName: "MalQuery", read: true, write: false, unlocks: "/malquery hash lineage" },
    { consoleName: "Threat Graph", read: true, write: false, unlocks: "/pivot execution-lineage mode (hash-only)" },
    { consoleName: "Workflow", read: true, write: true, unlocks: "/workflows Fusion SOAR posture + on-demand execute" },
  ],
  identity: [
    { consoleName: "Identity Protection Sensors", read: true, write: false, unlocks: "/identity sensor posture (enforcement modes, status causes)" },
    { consoleName: "Identity Protection Entities", read: true, write: false, unlocks: "/identity risky users (GraphQL); /queue identity rows" },
    { consoleName: "Identity Protection Detections", read: true, write: false, unlocks: "/identity active IDP detections; /queue identity rows" },
    { consoleName: "Identity Protection Timeline", read: true, write: false, unlocks: "Per-entity activity timeline (used by /identity)" },
  ],
  // New in falcon-mcp 0.19.0 (Guardian module — the AIDR platform surface).
  // 25 read-only tools for AI-agent activity; backs the dashboard "AI agent
  // activity" tile. Staged — without AIDR:read the tile hides and the panel
  // reports scope-pending.
  aidr: [
    { consoleName: "AIDR", read: true, write: false, unlocks: "Dashboard “AI agent activity” tile (Guardian) — AI agents, sessions, tools, prompts, models, and Agentic Threat Scores in the tenant" },
  ],
  // New in falcon-mcp 0.10.0 (cloud + shield modules). Agent-reachable in
  // chat only — no dedicated page — so read-only and entirely optional;
  // unset scopes just return a scope-pending notice. Console scope names
  // derived from the FalconPy operations the modules call (cspm_evaluations
  // → Cloud Security API Detections; cloud_security_assets → Cloud Security
  // API Assets; *SuppressionRules → Cloud Security API Detections write;
  // ReadContainerCombined → Falcon Container Image; container kubernetes →
  // Kubernetes Protection; SHIELD *V3 → Falcon Shield). CrowdStrike has
  // renamed Cloud Security scopes across editions — match against your
  // tenant's actual API-scope list if a label differs.
  cloud: [
    { consoleName: "Cloud Security API Detections", read: true, write: true, unlocks: "Cloud misconfiguration (IOM/IOA) findings; suppression rules (write — approval-gated)" },
    { consoleName: "Cloud Security API Assets", read: true, write: false, unlocks: "Cloud asset inventory (CSPM)" },
    { consoleName: "Falcon Container Image", read: true, write: false, unlocks: "Container image vulnerability search" },
    { consoleName: "Kubernetes Protection", read: true, write: false, unlocks: "Kubernetes container inventory + counts" },
    { consoleName: "Falcon Shield (SaaS Security)", read: true, write: false, unlocks: "SaaS posture: security checks, alerts, users / apps / devices, data shares, integrations, system logs" },
  ],
  optional: [
    { consoleName: "CAO Hunting", read: true, write: false, unlocks: "Tool surfaced but kept out of hot prompts; not in Falcon Go/Pro editions" },
  ],
};

// FALCON_MCP_MODULES tokens — these go into the comma-separated env var that
// configures which falcon-mcp modules to enable. Note these are NOT scope
// names; they're falcon-mcp module names (which may differ from the console
// scope label and reject underscored forms — `customioa` not `custom_ioa`).
const MCP_MODULES = [
  { token: "detections", needs: "Detections / Alerts read" },
  { token: "hosts", needs: "Hosts read (write for containment)" },
  { token: "spotlight", needs: "Vulnerabilities read" },
  { token: "intel", needs: "Falcon Intelligence Actors + Indicators read" },
  { token: "rtr", needs: "Real Time Response (read+write) + Admin (read+write)" },
  { token: "firewall", needs: "Firewall Management read+write" },
  { token: "customioa", needs: "Custom IOA Rules read+write (no underscore)" },
  { token: "discover", needs: "Discover read" },
  { token: "ioc", needs: "Indicators (Custom) read+write" },
  { token: "sensorusage", needs: "Sensor Usage read (no underscore)" },
  { token: "scheduledreports", needs: "Scheduled Reports read+write (no underscore)" },
  { token: "ngsiem", needs: "NGSIEM (Investigate) read" },
  { token: "cases", needs: "Cases read+write + Case Templates read (new in 0.10.0; replaced the removed `incidents` module)" },
  { token: "cloud", needs: "Cloud Security API Detections + Cloud Security API Assets + Falcon Container Image + Kubernetes Protection read (new in 0.10.0)" },
  { token: "shield", needs: "Falcon Shield / SaaS Security read (new in 0.10.0)" },
  { token: "guardian", needs: "AIDR read (new in 0.19.0 — AI-agent activity / Guardian)" },
];

// Console scope name → the live capability key reported by /api/health for the
// ACTIVE environment. Only the staged / optional surfaces are probed per-env
// (that's where availability actually varies); the core scopes are baseline —
// the app doesn't function without them and they aren't probed individually, so
// they're intentionally unmapped and render as "not checked" rather than a
// misleading red. Keys must match FalconMcpCapabilities (lib/health.ts).
const CAP_BY_CONSOLE: Record<string, string> = {
  Cases: "cases",
  "Case Templates": "cases",
  "Assets (Falcon Discover)": "discover",
  Quarantine: "quarantine",
  "Correlation Rules": "correlationRules",
  "Data Protection": "dataProtection",
  "Falcon Intelligence: Actors": "intel",
  "Falcon Intelligence: Indicators": "intel",
  "Monitoring Rules (Falcon Intelligence Recon)": "recon",
  MalQuery: "malQuery",
  "Threat Graph": "threatGraph",
  Workflow: "workflows",
  "Identity Protection Sensors": "idp",
  "Identity Protection Entities": "idp",
  "Identity Protection Detections": "idp",
  "Identity Protection Timeline": "idp",
  AIDR: "guardian",
};

export type ScopeCapStates = Record<string, boolean | undefined>;

function ScopeBlip({ state }: { state: boolean | undefined }) {
  const cls =
    state === true
      ? "bg-emerald-400"
      : state === false
        ? "bg-red-500"
        : "bg-neutral-700";
  const title =
    state === true
      ? "Available on the active environment"
      : state === false
        ? "Not granted on the active environment"
        : "Not checked (baseline / core scope, or no live probe)";
  return (
    <span
      className={`mt-1 inline-block h-2 w-2 shrink-0 rounded-full ${cls}`}
      title={title}
      aria-label={title}
    />
  );
}

function TierBlock({
  title,
  rows,
  capStates,
}: {
  title: string;
  rows: ScopeRow[];
  capStates?: ScopeCapStates;
}) {
  return (
    <div>
      <div className="mb-1.5 font-mono text-[11px] font-semibold uppercase tracking-[0.14em] text-neutral-300">
        {title}
      </div>
      <ul className="space-y-1.5">
        {rows.map((s) => (
          <li
            key={s.consoleName}
            className="grid grid-cols-[1fr_auto] gap-x-3 rounded border border-neutral-900 bg-neutral-950/60 px-2.5 py-1.5"
          >
            <div className="flex min-w-0 items-start gap-2">
              {capStates && <ScopeBlip state={capStates[CAP_BY_CONSOLE[s.consoleName]]} />}
              <div className="min-w-0">
                <div className="font-mono text-[12px] text-neutral-200">{s.consoleName}</div>
                <div className="mt-0.5 text-[11px] leading-snug text-neutral-500">{s.unlocks}</div>
              </div>
            </div>
            <div className="flex shrink-0 items-start gap-1 pt-0.5">
              {s.read && (
                <span className="rounded border border-neutral-700 bg-neutral-900 px-1 py-0.5 font-mono text-[9px] uppercase tracking-[0.1em] text-neutral-300">
                  read
                </span>
              )}
              {s.write && (
                <span className="rounded border border-amber-900/60 bg-amber-950/40 px-1 py-0.5 font-mono text-[9px] uppercase tracking-[0.1em] text-amber-200">
                  write
                </span>
              )}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default function ScopeChecklist({
  initiallyOpen = false,
  capStates,
  envName,
}: {
  initiallyOpen?: boolean;
  /** Live per-environment capability map from /api/health. When provided, each
   *  mappable scope row shows a green/red/neutral availability blip. Omitted on
   *  the pre-registration /register surface (nothing to probe yet). */
  capStates?: ScopeCapStates;
  envName?: string;
} = {}) {
  const [open, setOpen] = useState(initiallyOpen);

  return (
    <div className="rounded-md border border-neutral-800 bg-neutral-950/60">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between gap-2 px-3 py-2 text-left text-sm text-neutral-200 hover:bg-neutral-900/40"
      >
        <span className="flex items-center gap-2">
          {open ? (
            <ChevronDown className="h-4 w-4 text-neutral-500" />
          ) : (
            <ChevronRight className="h-4 w-4 text-neutral-500" />
          )}
          <span>What Falcon API scopes does this app need?</span>
        </span>
        <span className="font-mono text-[11px] uppercase tracking-[0.12em] text-neutral-500">
          {open ? "hide" : "show"}
        </span>
      </button>

      {open && (
        <div className="space-y-4 border-t border-neutral-800 px-3 py-3">
          <p className="text-[12px] leading-snug text-neutral-400">
            Tick these on the API client whose ID + secret you paste above. Falcon
            console → <span className="font-mono">Support → API Clients and Keys</span>.
            Surfaces backed by missing scopes degrade cleanly (the page renders a
            scope-pending message and the sidebar nav item hides) — you can grant
            more later without touching this app.
          </p>

          {capStates && (
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 rounded border border-neutral-900 bg-neutral-950/60 px-2.5 py-2 text-[11px] text-neutral-400">
              <span className="text-neutral-500">
                Availability on{" "}
                <span className="text-neutral-300">{envName ?? "the active environment"}</span>:
              </span>
              <span className="flex items-center gap-1.5">
                <span className="inline-block h-2 w-2 rounded-full bg-emerald-400" /> available
              </span>
              <span className="flex items-center gap-1.5">
                <span className="inline-block h-2 w-2 rounded-full bg-red-500" /> not granted
              </span>
              <span className="flex items-center gap-1.5">
                <span className="inline-block h-2 w-2 rounded-full bg-neutral-700" /> not checked
                (core / baseline)
              </span>
            </div>
          )}

          <TierBlock title="Core endpoint security (recommended for everyone)" rows={SCOPES.core} capStates={capStates} />
          <TierBlock title="Asset inventory (grant to light up /discover)" rows={SCOPES.discover} capStates={capStates} />
          <TierBlock title="Case management (new — grant to light up /cases)" rows={SCOPES.cases} capStates={capStates} />
          <TierBlock title="Quarantine · Correlation Rules · Data Protection" rows={SCOPES.falcon011} capStates={capStates} />
          <TierBlock title="Threat intelligence + hunting" rows={SCOPES.intel} capStates={capStates} />
          <TierBlock
            title="Identity Protection (only if your tenant has IDP licensed + AD sensors deployed)"
            rows={SCOPES.identity}
            capStates={capStates}
          />
          <TierBlock
            title="AI agent activity — Guardian / AIDR"
            rows={SCOPES.aidr}
            capStates={capStates}
          />
          <TierBlock
            title="Cloud + SaaS Security (agent-only in chat; no page; entirely optional)"
            rows={SCOPES.cloud}
            capStates={capStates}
          />
          <TierBlock title="Tool surfaced but not actively required" rows={SCOPES.optional} capStates={capStates} />

          <p className="text-[11px] leading-snug text-neutral-500">
            The Cloud + SaaS Security tools are reachable only when the agent
            chooses them in chat — there is no dedicated page and nothing
            depends on them. Without the scope they return a scope-pending
            notice and nothing breaks. CrowdStrike has relabelled Cloud
            Security scopes across editions; if a name above doesn&apos;t
            match your tenant&apos;s API-scope list, grant the closest Cloud
            Security / SaaS Security equivalent.
          </p>

          <div>
            <div className="mb-1.5 font-mono text-[11px] font-semibold uppercase tracking-[0.14em] text-neutral-300">
              FALCON_MCP_MODULES tokens (the Modules field above)
            </div>
            <p className="text-[11px] leading-snug text-neutral-500">
              The Modules field uses eyas-mcp module names, not console scope
              labels. Two gotchas:{" "}
              <span className="text-neutral-300">no underscores</span> (use{" "}
              <span className="font-mono">customioa</span>, not{" "}
              <span className="font-mono">custom_ioa</span>); modules silently
              omit if their underlying scope isn't granted.
            </p>
            <ul className="mt-1.5 space-y-0.5">
              {MCP_MODULES.map((m) => (
                <li
                  key={m.token}
                  className="grid grid-cols-[8rem_1fr] gap-x-2 px-2 py-0.5 text-[11px]"
                >
                  <span className="font-mono text-neutral-200">{m.token}</span>
                  <span className="text-neutral-500">{m.needs}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}
