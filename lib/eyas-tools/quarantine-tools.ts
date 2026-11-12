import { jsonResult, type EyasTool } from "./types";
import {
  adoptQuarantineHostGroup,
  CANONICAL_GROUP_NAME,
  createQuarantineHostGroup,
  diagnoseIrReadiness,
  diagnoseQuarantineSetup,
} from "./quarantine";
import { detachPreventionPolicy, provisionQuarantinePolicy } from "./quarantine-provision";

// Agent-facing tools for IR quarantine setup and readiness. Descriptions are
// carried over from the former sidecar tools, with the group id now read from
// the active environment rather than a spawn-time env var.

export const QUARANTINE_TOOLS: EyasTool[] = [
  {
    name: "extras_diagnose_quarantine_setup",
    description: [
      "Read-only diagnostic for the IR quarantine setup state on this tenant.",
      "",
      "Detects which migration case the tenant is in and returns the right next-step CTA for the /config UI to surface:",
      "",
      "  - ``no_group_id`` — no quarantine group configured. Recommendation: run ``extras_create_quarantine_host_group``.",
      "  - ``group_missing`` — configured group id doesn't exist. Recommendation: re-create.",
      '  - ``A_no_policy`` — group has no dedicated prevention policy attached. Recommendation: ``extras_provision_quarantine_policy`` with ``mode="adopt"``.',
      '  - ``B_dedicated_single_group`` — group has a policy attached only to it. Recommendation: same, ``mode="adopt"``.',
      '  - ``C_shared_policy`` — group has a policy that\'s also attached to other groups. Recommendation: ``extras_provision_quarantine_policy`` with ``mode="create_dedicated"`` (creates a brand-new dedicated policy, leaves the existing shared one alone).',
      "  - ``ready`` — all three platform policies are app-managed, AGGRESSIVE, and the IR-readiness IOA exclusion is in place.",
      "",
      "Args:",
      "    host_group_id: Defaults to the active environment's IR quarantine group.",
    ].join("\n"),
    input_schema: {
      type: "object",
      properties: {
        host_group_id: { anyOf: [{ type: "string" }, { type: "null" }], default: null, title: "Host Group Id" },
      },
    },
    run: async (input, ctx) =>
      jsonResult(await diagnoseQuarantineSetup(ctx, typeof input.host_group_id === "string" ? input.host_group_id : null)),
  },
  {
    name: "extras_create_quarantine_host_group",
    description: [
      "Create a new STATIC host group for IR quarantine. WRITE — approval-gated.",
      "",
      "Creates the host group with the canonical app-managed naming so it's identifiable later. Returns ``{ok, id, name, group_type}``. The new id is saved as the active environment's IR quarantine group automatically.",
      "",
      "The created group is empty — no hosts attached. Use ``extras_provision_quarantine_policy`` next to attach the prevention policies.",
      "",
      "Args:",
      `    name: Group name (default: canonical "${CANONICAL_GROUP_NAME}").`,
      "    description: Optional override for the group description.",
    ].join("\n"),
    input_schema: {
      type: "object",
      properties: {
        name: { default: CANONICAL_GROUP_NAME, title: "Name", type: "string" },
        description: { anyOf: [{ type: "string" }, { type: "null" }], default: null, title: "Description" },
      },
    },
    run: async (input, ctx) => jsonResult(await createQuarantineHostGroup(ctx, input)),
  },
  {
    name: "extras_adopt_quarantine_host_group",
    description: [
      "Adopt an EXISTING host group as the IR quarantine group. WRITE — approval-gated.",
      "",
      "Looks up a host group by exact name in the active tenant and returns ``{ok, id, name, group_type}``. The chat auto-save hook persists the returned ``id`` as the active environment's IR quarantine group. Use this when the group has already been created out-of-band (e.g. from a previous install) and you just need Project Eyas to know its id. Any name works, not only the canonical one.",
      "",
      "Returns ``ok: false`` if zero or more than one group matches the name.",
      "",
      "Args:",
      `    name: Exact group name (default: canonical "${CANONICAL_GROUP_NAME}").`,
    ].join("\n"),
    input_schema: {
      type: "object",
      properties: { name: { default: CANONICAL_GROUP_NAME, title: "Name", type: "string" } },
    },
    run: async (input, ctx) => jsonResult(await adoptQuarantineHostGroup(ctx, input)),
  },
  {
    name: "extras_diagnose_ir_readiness",
    description: [
      "Diagnose whether the IR workflow is correctly provisioned on this tenant. Read-only.",
      "",
      "Checks: (1) the active environment has an IR quarantine group set; (2) the configured group actually exists in Falcon; (3) IOA exclusions scoped to that group are enumerated; (4) heuristically determines whether the RTR-runscript-preamble exclusion is present (the exclusion that prevents the quarantine policy from blocking RTR cleanup primitives); (5) auto-discovers a `pattern_id` from a recent PShellMimikatz detection on the tenant if available, so the create-exclusion call can be composed concretely.",
      "",
      "Returns `ready=true` only when all checks pass. When prerequisites are missing, the response includes `remediation.tool_calls[]` — concrete `extras_create_ioa_exclusion` invocations the operator can review and fire (the create itself is approval-gated; this diagnostic does not write).",
      "",
      "Why this matters: IR's Phase 2 cleanup primitives all flow through `runscript -CloudFile=`, which the sensor invokes with a fixed `-EncodedCommand` PowerShell preamble. On a properly aggressive quarantine prevention policy, that preamble is *blocked at the sensor* — every cleanup attempt fails and Phase 2 is silently a no-op. The IOA exclusion this diagnostic recommends scopes the preamble pattern to the quarantine host group only, keeping production hosts fully covered.",
    ].join("\n"),
    input_schema: { type: "object", properties: {} },
    run: async (_input, ctx) => jsonResult(await diagnoseIrReadiness(ctx)),
  },
  {
    name: "extras_provision_quarantine_policy",
    description: [
      "Provision IR quarantine prevention policies for the named host group. WRITE — approval-gated; one approval covers the whole chain below.",
      "",
      "Per platform (Windows / macOS / Linux):",
      '  - mode="adopt": adopt the existing policy bound to this group (rename to canonical, push AGGRESSIVE sliders), or attach a fresh canonical policy if none exists. Use for migration cases A and B.',
      '  - mode="create_dedicated": always create a brand-new dedicated policy bound only to this group, leave any existing shared policy alone. Use for migration case C.',
      "",
      "Pushes EVERY slider on the policy (detection + prevention pairs and detection-only sliders) to AGGRESSIVE, AND enables EVERY boolean behavioral toggle (script monitoring, encoded-command, volume-shadow-copy protection, etc.). Operates on setting shape, not a hard-coded list, so the policy schema can evolve without code changes.",
      "",
      "Then moves each IR policy to the top of its platform's precedence (a quarantined host keeps its other groups; the IR policy wins by precedence), and installs the IR-readiness IOA exclusion scoped to the group if it is missing and a PShellMimikatz pattern_id can be resolved (otherwise the result carries a warning).",
      "",
      "Args:",
      "    host_group_id: The IR quarantine host group id.",
      '    mode: "adopt" (Cases A / B) or "create_dedicated" (Case C). Use ``extras_diagnose_quarantine_setup`` first to determine which.',
    ].join("\n"),
    input_schema: {
      type: "object",
      properties: {
        host_group_id: { title: "Host Group Id", type: "string" },
        mode: { default: "adopt", title: "Mode", type: "string" },
      },
      required: ["host_group_id"],
    },
    run: async (input, ctx) => jsonResult(await provisionQuarantinePolicy(ctx, input)),
  },
  {
    name: "extras_detach_prevention_policy_from_host_group",
    description: [
      "Detach a prevention policy from a host group. WRITE — approval-gated.",
      "",
      'Runs the prevention-policy action "remove-host-group". The policy itself is NOT deleted — it stays attached to whatever other host groups it was bound to. This is the inverse of the "add-host-group" action used during provisioning.',
      "",
      "Use case: an operator-created legacy policy is attached to multiple groups including the IR Quarantine or Shadow-AI Banned groups, and the operator wants to detach it from those specific groups so the new dedicated app-managed policies are the only ones applying via precedence.",
      "",
      "Args:",
      "    prevention_policy_id: The Prevention Policy id.",
      "    host_group_id: The Host Group id to detach from.",
    ].join("\n"),
    input_schema: {
      type: "object",
      properties: {
        prevention_policy_id: { title: "Prevention Policy Id", type: "string" },
        host_group_id: { title: "Host Group Id", type: "string" },
      },
      required: ["prevention_policy_id", "host_group_id"],
    },
    run: async (input, ctx) => jsonResult(await detachPreventionPolicy(ctx, input)),
  },
];
