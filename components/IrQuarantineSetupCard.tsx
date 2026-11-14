"use client";

import { ShieldAlert } from "lucide-react";
import HostGroupSetupCard, {
  StatusPanel,
  type SetupAction,
  type SetupCardConfig,
  type SetupDiagnostic,
  type SetupPolicy,
} from "@/components/HostGroupSetupCard";

// IR quarantine setup card — surfaced on /config so the operator can
// stand up (or migrate to) the canonical app-managed quarantine artifacts
// without leaving the app. Reads state from /api/ir-quarantine/diagnose; the
// shared card (HostGroupSetupCard) renders it.

type Diagnostic = Omit<SetupDiagnostic, "case" | "policies"> & {
  case?:
    | "no_group_id"
    | "group_missing"
    | "A_no_policy"
    | "B_dedicated_single_group"
    | "C_shared_policy"
    | "ready";
  policies?: Array<
    SetupPolicy & {
      settings_summary: Record<string, { detection: string | null; prevention: string | null }>;
    }
  >;
  ir_readiness_exclusion_present?: boolean;
};

function primerFor(a: SetupAction): string | null {
  if (a.tool === "extras_create_quarantine_host_group") {
    const name = (a.args.name as string) || "Project Eyas - IR Quarantine";
    return (
      `Create the IR quarantine host group on this tenant. Call ` +
      `extras_create_quarantine_host_group with name="${name}". The new group id is saved to the active environment automatically. Then continue straight on with extras_provision_quarantine_policy using that host_group_id (no manual /config step needed).`
    );
  }
  if (a.tool === "extras_provision_quarantine_policy") {
    const groupId = a.args.host_group_id as string;
    const mode = (a.args.mode as string) || "adopt";
    return (
      `Provision the IR quarantine prevention policies on this tenant. Call ` +
      `extras_provision_quarantine_policy with host_group_id="${groupId}" and mode="${mode}". ` +
      `Per platform (Windows, macOS, Linux), this ${mode === "create_dedicated" ? "creates dedicated policies" : "adopts the existing single-group policy or attaches a fresh canonical one"}, ` +
      `pushes AGGRESSIVE prevention sliders, and verifies the IR-readiness IOA exclusion. ` +
      `If the verification step returns a follow_up_tool_call, fire extras_create_ioa_exclusion with those args (separate approval).`
    );
  }
  return null;
}

const config: SetupCardConfig<Diagnostic> = {
  icon: ShieldAlert,
  title: "IR quarantine setup",
  intro: (
    <>
      The agentic IR workflow needs a dedicated host group with three
      platform-specific prevention policies (Windows, macOS, Linux), all set to
      AGGRESSIVE, plus an IOA exclusion that lets cleanup tooling run on
      quarantined hosts. This card stands them up — or detects what you already
      have and standardizes around it.
    </>
  ),
  diagnoseEndpoint: "/api/ir-quarantine/diagnose",
  adoptEndpoint: "/api/ir-quarantine/adopt",
  applyEndpoint: "/api/environments/active/ir-quarantine-group",
  defaultGroupName: "Project Eyas - IR Quarantine",
  applyLabel: "Or paste the IR quarantine group id",
  noGroupText:
    "No host group is set on the active environment. Adopt an existing one by name below, paste its id, or click the action further down to create one with the canonical naming.",
  casePill: {
    no_group_id: { label: "Not configured", cls: "border-amber-800/60 bg-amber-950/30 text-amber-200" },
    group_missing: { label: "Group missing", cls: "border-red-800/60 bg-red-950/30 text-oxblood-200" },
    A_no_policy: { label: "Group only — no policy", cls: "border-amber-800/60 bg-amber-950/30 text-amber-200" },
    B_dedicated_single_group: { label: "Adopt + standardize", cls: "border-sky-800/60 bg-sky-950/30 text-sky-200" },
    C_shared_policy: { label: "Shared policy — needs dedicated", cls: "border-amber-800/60 bg-amber-950/30 text-amber-200" },
    ready: { label: "Ready", cls: "border-emerald-800/60 bg-emerald-950/30 text-emerald-200" },
  },
  primerFor,
  statusPanel: (data) => (
    <StatusPanel title="IR-readiness IOA exclusion">
      {data.ir_readiness_exclusion_present
        ? "Present — RTR runscript preamble is excluded on this group's policies."
        : "Not present — Phase 2 cleanup will be sensor-blocked until the exclusion is created. The provision action below will compose the call shape; firing extras_create_ioa_exclusion is its own approval."}
    </StatusPanel>
  ),
  readyText: "IR quarantine is fully provisioned on this tenant. The IR workflow can run cleanly.",
};

export default function IrQuarantineSetupCard() {
  return <HostGroupSetupCard config={config} />;
}
