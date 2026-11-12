import { jsonResult, type EyasTool, type EyasToolContext, type EyasToolResult } from "./types";

// Static host-group membership writes (formerly falcon-extras host_groups.py).
// Thin Eyas tools over eyas-mcp's falcon_perform_host_group_action, which
// takes explicit device ids and refuses dynamic or unknown groups itself
// (eyas-mcp ≥ 4ceadcd). The native stays hidden from the agent
// (NATIVE_WRITE_SUPPRESS): these names are what the IR / Shadow-AI playbooks
// call and what the IR release guard, ground truth and run analysis key on,
// so they keep their names, inputs and result shape.

const AID_RX = /^[0-9a-fA-F]{32}$/;
const MAX_DEVICE_IDS = 500;

const fail = (error: string, extra: Record<string, unknown> = {}): EyasToolResult =>
  jsonResult({ ok: false, error, ...extra });

export async function hostGroupAction(
  action: "add-hosts" | "remove-hosts",
  input: Record<string, unknown>,
  ctx: EyasToolContext,
): Promise<EyasToolResult> {
  const groupId = input.group_id;
  if (typeof groupId !== "string" || !groupId) return fail("group_id required");
  const deviceIds = input.device_ids;
  if (!Array.isArray(deviceIds) || deviceIds.length === 0) return fail("device_ids must be a non-empty list");
  if (deviceIds.length > MAX_DEVICE_IDS) return fail(`max ${MAX_DEVICE_IDS} device_ids per call`);
  // Reject-don't-escape: anything that isn't a 32-hex AID is a typo or an
  // injection attempt, never a real host.
  for (const d of deviceIds) {
    if (typeof d !== "string" || !AID_RX.test(d)) {
      return fail(`invalid device_id ${JSON.stringify(d)}: must be 32 hexadecimal characters`);
    }
  }
  const r = await ctx.callNative("falcon_perform_host_group_action", {
    action_name: action,
    ids: [groupId],
    device_ids: deviceIds,
  });
  if (r.error) return fail(r.error);
  return jsonResult({
    ok: true,
    action,
    group_id: groupId,
    device_ids: deviceIds,
    resources: r.obj ? [r.obj] : [],
  });
}

const MEMBERSHIP_SCHEMA = {
  type: "object" as const,
  properties: {
    group_id: { type: "string", title: "Group Id" },
    device_ids: { type: "array", items: { type: "string" }, title: "Device Ids" },
  },
  required: ["group_id", "device_ids"],
};

export const HOST_GROUP_TOOLS: EyasTool[] = [
  {
    name: "extras_host_group_add_members",
    description: [
      "Add one or more hosts to a static Falcon Host Group. WRITE ACTION — requires explicit user approval in the UI before execution.",
      "",
      "Accepts both 'static' (added-by-name) and 'staticByID' (added-by-AID) group flavors. Dynamic groups (group_type='dynamic') determine membership via their assignment_rule FQL — those are refused before anything changes.",
      "",
      "Args:",
      "    group_id: The host group id (must be static or staticByID). From falcon_search_host_groups.",
      "    device_ids: List of Falcon device (AID) IDs to add. Cap 500 per call.",
    ].join("\n"),
    input_schema: MEMBERSHIP_SCHEMA,
    run: (input, ctx) => hostGroupAction("add-hosts", input, ctx),
  },
  {
    name: "extras_host_group_remove_members",
    description: [
      "Remove one or more hosts from a static Falcon Host Group. WRITE ACTION — requires explicit user approval in the UI before execution.",
      "",
      "Accepts both 'static' and 'staticByID' group flavors.",
      "",
      "Args:",
      "    group_id: The host group id (must be static or staticByID).",
      "    device_ids: List of Falcon device (AID) IDs to remove. Cap 500 per call.",
    ].join("\n"),
    input_schema: MEMBERSHIP_SCHEMA,
    run: (input, ctx) => hostGroupAction("remove-hosts", input, ctx),
  },
];
