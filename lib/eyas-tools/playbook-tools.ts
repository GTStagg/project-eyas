import type { EyasTool } from "./types";
import {
  renderDataProtectionPlaybook,
  renderIdentityIrPlaybook,
  renderIrPlaybook,
  renderShadowAiPlaybook,
} from "./playbooks";

// The four workflow playbook tools. The host-group ids come from the active
// environment in the config store, read at call time, so a group created or
// adopted earlier in the same chat turn (auto-saved by the chat route) is
// already visible. The config module is imported lazily so the tool list can
// be loaded without opening the database (scripts/test-tool-classification.mjs).

async function activeGroupIds(): Promise<{ quarantine?: string; banned?: string }> {
  const { getRuntimeConfig } = await import("@/lib/config/runtime");
  const cfg = getRuntimeConfig();
  return { quarantine: cfg.irQuarantineGroupId, banned: cfg.shadowAiBannedGroupId };
}

const DEVICE_ID_SCHEMA = {
  type: "object" as const,
  properties: {
    device_id: { type: "string", description: "Falcon AID of the target host." },
  },
  required: ["device_id"],
};

export const PLAYBOOK_TOOLS: EyasTool[] = [
  {
    name: "extras_ir_workflow_playbook",
    description: [
      "Return the agentic IR workflow playbook for a single host. Read-only.",
      "",
      "Call this when the operator asks for an agentic IR / quarantine-and-clean workflow on a specific host (e.g. they say \"run the IR workflow on WIN11-HR-03\" or click the IR button on the /hosts page). The returned `playbook` text is your working instruction set for the rest of the conversation — follow it verbatim, phase by phase.",
      "",
      "The playbook is parameterized with the target device_id and the operator-configured quarantine host group id. Returns ok=false with a clear error if the active environment has no IR quarantine host group set.",
    ].join("\n"),
    input_schema: DEVICE_ID_SCHEMA,
    rawResult: true,
    run: async (input) => renderIrPlaybook(input, (await activeGroupIds()).quarantine),
  },
  {
    name: "extras_shadow_ai_workflow_playbook",
    description: [
      "Return the agentic Shadow-AI ban-and-clean workflow playbook for one host. Read-only.",
      "",
      "Call this when the operator clicks \"Ban + Clean\" on a host in /shadow-ai or asks for the agentic Shadow-AI workflow on a specific host. The returned `playbook` text is your working instruction set for the rest of the conversation — follow it phase by phase.",
      "",
      "The playbook is parameterized with the target device_id and the operator-configured banned host group id. Returns ok=false with a clear error if the active environment has no Shadow-AI banned host group set.",
    ].join("\n"),
    input_schema: DEVICE_ID_SCHEMA,
    rawResult: true,
    run: async (input) => renderShadowAiPlaybook(input, (await activeGroupIds()).banned),
  },
  {
    name: "extras_identity_ir_workflow_playbook",
    description: [
      "Return the agentic identity-IR workflow playbook for a specific entity. Read-only. Mirrors extras_ir_workflow_playbook (host) but pivots on an identity entity rather than an AID.",
      "",
      "The agent calls this when the operator asks for an agentic identity IR workflow on a user; the returned text becomes the agent's working playbook for the rest of the conversation. The defining shape of identity IR is the **endpoint cascade** — Falcon's IDP API surface doesn't include account-disable / session-kill / password-reset, so the load-bearing remediation is to run the host IR playbook on each endpoint the user has been logged into recently.",
      "",
      "At least one of entity_id or sam_account_name must be provided.",
    ].join("\n"),
    input_schema: {
      type: "object",
      properties: {
        entity_id: { type: "string", description: "Optional. IDP entity id from the GraphQL API." },
        sam_account_name: { type: "string", description: "Optional. AD samAccountName." },
      },
    },
    rawResult: true,
    run: async (input) => renderIdentityIrPlaybook(input),
  },
  {
    name: "extras_data_protection_provision_playbook",
    description: [
      "Return the agentic Data Protection provisioning playbook. Read-only.",
      "",
      "Call this when the operator asks to provision / set up / stand up Data Protection (DLP) coverage for a sensitive-data type — e.g. \"watch for SSNs on Windows\", \"protect our internal codenames\", or they click \"Provision coverage\" on the /data-protection page. The returned `playbook` text is your working instruction set for the rest of the conversation: precheck existing coverage, synthesize + validate the regexes from the operator's description, then build the monitor-first content-pattern -> classification -> policy chain (each create approval-gated). Follow it step by step.",
    ].join("\n"),
    input_schema: { type: "object", properties: {} },
    rawResult: true,
    run: async () => renderDataProtectionPlaybook(),
  },
];
