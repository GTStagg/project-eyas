"use client";

import { Sparkles } from "lucide-react";
import HostGroupSetupCard, {
  PolicyBadge,
  StatusPanel,
  type SetupAction,
  type SetupCardConfig,
  type SetupDiagnostic,
  type SetupPolicy,
} from "@/components/HostGroupSetupCard";

// Sister card to IrQuarantineSetupCard. Same per-state CTA pattern, same
// chat-primer hand-off, same "managed by Eyas" / "shared with other groups"
// badges (all in HostGroupSetupCard). Reads from /api/shadow-ai-banned/diagnose.

type FollowUp = {
  tool: string;
  args: Record<string, unknown>;
  platform: string;
  missing_rules?: string[];
};

type Diagnostic = Omit<SetupDiagnostic, "case" | "policies" | "recommended_action"> & {
  case?:
    | "no_group_id"
    | "group_missing"
    | "A_no_policy"
    | "B_dedicated_single_group"
    | "C_shared_policy"
    | "rules_incomplete"
    | "ready";
  policies?: Array<
    SetupPolicy & {
      rule_group_bound: boolean;
      rules_in_group?: number;
      rules_expected?: number;
      rules_missing?: string[];
    }
  >;
  rule_group_attached?: boolean;
  recommended_action?: (SetupAction & { follow_up_tool_calls?: FollowUp[] }) | null;
};

function primerFor(a: NonNullable<Diagnostic["recommended_action"]>): string | null {
  if (a.tool === "extras_create_shadow_ai_banned_host_group") {
    const name = (a.args.name as string) || "Project Eyas - Shadow-AI Banned";
    return (
      `Create the Shadow-AI Banned host group on this tenant. Call ` +
      `extras_create_shadow_ai_banned_host_group with name="${name}". The new group id is saved to the active environment automatically. Then continue straight on with extras_provision_shadow_ai_banned_policy using that host_group_id (no manual /config step needed).`
    );
  }
  if (a.tool === "extras_provision_shadow_ai_banned_policy") {
    const groupId = a.args.host_group_id as string;
    const mode = (a.args.mode as string) || "adopt";
    return (
      `Provision the Shadow-AI Banned prevention policies on this tenant. Call ` +
      `extras_provision_shadow_ai_banned_policy with host_group_id="${groupId}" and mode="${mode}". ` +
      `Per platform (Windows, macOS, Linux), this ${mode === "create_dedicated" ? "creates dedicated policies" : "adopts the existing single-group policy or attaches a fresh canonical one"}, ` +
      `pushes AGGRESSIVE sliders + enabled toggles, and sets precedence above standard / below IR Quarantine. ` +
      `Then for each follow_up_tool_call returned, fire extras_shadow_ai_adopt_prevention with those args (separate approval) so the Shadow-AI rule group is authored and bound to the new policies.`
    );
  }
  if (a.tool === "extras_shadow_ai_adopt_prevention" && a.follow_up_tool_calls?.length) {
    // Rule corpus refresh — multi-call. Fire one extras_shadow_ai_adopt_prevention
    // per affected platform.
    const callList = a.follow_up_tool_calls
      .map(
        (c) =>
          `extras_shadow_ai_adopt_prevention with prevention_policy_id="${c.args.prevention_policy_id}", ` +
          `platform="${c.args.platform}", mode="${c.args.mode || "block"}", comment="${c.args.comment}"`,
      )
      .join("; ");
    return `Refresh the Shadow-AI rule corpus on this tenant — some rules from the per-platform corpus aren't in the rule groups (the previous adoption run authored a partial set). Fire each of these calls (separate approvals): ${callList}. The tool is idempotent — already-present rules dedupe by name; only the missing rules will be authored.`;
  }
  return null;
}

const config: SetupCardConfig<Diagnostic> = {
  icon: Sparkles,
  title: "Shadow-AI Banned setup",
  intro: (
    <>
      Default-allow tenant: AI tooling is permitted everywhere unless an
      operator drops a host into the Shadow-AI Banned group. This card stands up
      the host group, three platform-specific prevention policies, and the
      Shadow-AI Custom IOA rule group that fires on banned hosts. Posture stays
      untouched on non-banned hosts; precedence ensures the banned policy wins
      when applied.
    </>
  ),
  diagnoseEndpoint: "/api/shadow-ai-banned/diagnose",
  adoptEndpoint: "/api/shadow-ai-banned/adopt",
  applyEndpoint: "/api/environments/active/shadow-ai-banned-group",
  defaultGroupName: "Project Eyas - Shadow-AI Banned",
  applyLabel: "Or paste the Shadow-AI Banned group id",
  noGroupText:
    "No Shadow-AI Banned host group is set on the active environment. Adopt an existing one by name below, paste its id, or click the action further down to create one with the canonical naming.",
  casePill: {
    no_group_id: { label: "Not configured", cls: "border-amber-800/60 bg-amber-950/30 text-amber-200" },
    group_missing: { label: "Group missing", cls: "border-red-800/60 bg-red-950/30 text-oxblood-200" },
    A_no_policy: { label: "Group only — no policy", cls: "border-amber-800/60 bg-amber-950/30 text-amber-200" },
    B_dedicated_single_group: { label: "Adopt + standardize", cls: "border-sky-800/60 bg-sky-950/30 text-sky-200" },
    C_shared_policy: { label: "Shared policy — needs dedicated", cls: "border-amber-800/60 bg-amber-950/30 text-amber-200" },
    rules_incomplete: { label: "Rule corpus incomplete", cls: "border-amber-800/60 bg-amber-950/30 text-amber-200" },
    ready: { label: "Ready", cls: "border-emerald-800/60 bg-emerald-950/30 text-emerald-200" },
  },
  primerFor,
  policyBadges: (p) => (
    <>
      {p.rule_group_bound && <PolicyBadge tone="emerald">rule group attached</PolicyBadge>}
      {p.rules_in_group !== undefined && p.rules_expected !== undefined && (
        <PolicyBadge
          tone={p.rules_missing && p.rules_missing.length > 0 ? "amber" : "neutral"}
          title={p.rules_missing?.length ? `missing: ${p.rules_missing.join(", ")}` : undefined}
        >
          {p.rules_in_group}/{p.rules_expected} rules
        </PolicyBadge>
      )}
    </>
  ),
  statusPanel: (data) => (
    <StatusPanel title="Shadow-AI Custom IOA rule group">
      {data.rule_group_attached
        ? "Attached — the Shadow-AI rule corpus fires for hosts in the banned group."
        : "Not attached — banned-group hosts won't actually have AI tooling blocked until the rule group is bound. The provisioning action below returns the follow-up calls to attach it (one separate approval per policy)."}
    </StatusPanel>
  ),
  readyText: "Shadow-AI Banned is fully provisioned. Drop hosts into the banned group from /hosts to enforce.",
};

export default function ShadowAiBannedSetupCard() {
  return <HostGroupSetupCard config={config} />;
}
