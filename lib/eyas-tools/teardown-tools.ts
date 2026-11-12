import { jsonResult, type EyasTool } from "./types";
import { deleteIoaRuleGroup, deletePreventionPolicy, teardownProjectEyasManaged } from "./teardown";

// Agent-facing teardown tools. Descriptions are carried over from the former
// sidecar tools.

export const TEARDOWN_TOOLS: EyasTool[] = [
  {
    name: "extras_teardown_project_eyas_managed",
    description: [
      "Wipe all canonical Project Eyas-managed objects from the tenant. WRITE (in execute mode) — approval-gated.",
      "",
      "Discovers host groups, prevention policies, custom IOA rule groups, and the IR-readiness IOA exclusions that Project Eyas created (matched by canonical name prefix, the active env's saved group ids, and the RTR-preamble exclusion marker), and tears them down in Falcon-enforced dependency order:",
      "",
      "  1. Detach prevention policies from host groups",
      "  2. Disable prevention policies",
      "  3. Delete prevention policies",
      "  4. Delete custom IOA rule groups",
      "  5. Delete IR-readiness IOA exclusions",
      "  6. Delete host groups",
      "",
      "Use during demo cycles or dev resets to return the tenant to a clean state before re-running the /config setup cards.",
      "",
      "The active env's saved ``irQuarantineGroupId`` + ``shadowAiBannedGroupId`` are NOT cleared automatically — operator clears them via the /config Clear button after this completes, OR re-provisions fresh groups (the auto-save hook overwrites with the new id).",
      "",
      "Args:",
      "    dry_run: When True (default), returns a structured plan without touching the tenant. When False, executes the teardown and returns per-step results.",
    ].join("\n"),
    input_schema: {
      type: "object",
      properties: { dry_run: { default: true, title: "Dry Run", type: "boolean" } },
    },
    run: async (input, ctx) => jsonResult(await teardownProjectEyasManaged(ctx, input)),
  },
  {
    name: "extras_delete_prevention_policy",
    description: [
      "Delete a single Falcon prevention policy by id. WRITE — approval-gated.",
      "",
      "The policy MUST already be detached from every host group (Falcon refuses delete on still-attached policies). This tool disables the policy before delete (Falcon also refuses delete on enabled policies). Use ``extras_detach_prevention_policy_from_host_group`` to detach first.",
      "",
      "Args:",
      "    prevention_policy_id: Prevention policy id.",
    ].join("\n"),
    input_schema: {
      type: "object",
      properties: { prevention_policy_id: { title: "Prevention Policy Id", type: "string" } },
      required: ["prevention_policy_id"],
    },
    run: async (input, ctx) => jsonResult(await deletePreventionPolicy(ctx, input)),
  },
  {
    name: "extras_delete_ioa_rule_group",
    description: [
      "Delete a single Custom IOA rule group by id. WRITE — approval-gated.",
      "",
      "Falcon refuses delete if the rule group is still bound to any prevention policy — delete the binding policies first, or unbind via a policy update.",
      "",
      "Args:",
      "    rule_group_id: Custom IOA rule group id.",
      "    comment: Reason for deletion (Falcon audit-trail field).",
    ].join("\n"),
    input_schema: {
      type: "object",
      properties: {
        rule_group_id: { title: "Rule Group Id", type: "string" },
        comment: { default: "Project Eyas teardown", title: "Comment", type: "string" },
      },
      required: ["rule_group_id"],
    },
    run: async (input, ctx) => jsonResult(await deleteIoaRuleGroup(ctx, input)),
  },
];
