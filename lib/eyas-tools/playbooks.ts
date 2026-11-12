import { jsonResult, type EyasToolResult } from "./types";
import { irPlaybookText } from "./playbooks/ir";
import { identityIrPlaybookText } from "./playbooks/identity-ir";
import { shadowAiPlaybookText } from "./playbooks/shadow-ai";
import { dataProtectionPlaybookText } from "./playbooks/data-protection";

// The four workflow playbooks (formerly falcon-extras *_playbook.py). Their
// results reach the model UNFENCED (agent-loop.ts UNFENCED_RESULT_TOOLS) —
// the text is the agent's instruction set — so every interpolated value is
// reject-validated first: anything that could carry markdown or instructions
// (backticks, newlines, …) is refused, never escaped.
//
// Pure renderers (no config or I/O) so scripts/test-playbooks.mjs can check
// them; the tool definitions that read the config store are in
// playbook-tools.ts.

const AID_RX = /^[0-9a-fA-F]{32}$/;
const GROUP_ID_RX = /^[A-Za-z0-9-]{1,64}$/;
const ENTITY_ID_RX = /^[A-Za-z0-9-]{1,128}$/;
const SAM_RX = /^[A-Za-z0-9 ._@$'-]{1,256}$/;

const fail = (error: string): EyasToolResult => jsonResult({ ok: false, error });

function str(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}

function checkAid(input: Record<string, unknown>): { aid: string } | { error: EyasToolResult } {
  const aid = str(input.device_id);
  if (!aid) return { error: fail("device_id required") };
  if (!AID_RX.test(aid)) {
    return { error: fail("device_id must be a host AID: 32 hexadecimal characters.") };
  }
  return { aid };
}

export function renderIrPlaybook(input: Record<string, unknown>, quarantineGroupId: string | undefined): EyasToolResult {
  const a = checkAid(input);
  if ("error" in a) return a.error;
  if (!quarantineGroupId) {
    return fail(
      'The active environment\'s "IR quarantine host group" is not set. Configure it on the ' +
        "active environment in /config (it must be the id of a static Falcon Host Group with an " +
        "aggressive prevention policy) before running the IR workflow.",
    );
  }
  if (!GROUP_ID_RX.test(quarantineGroupId)) {
    return fail('The active environment\'s "IR quarantine host group" id is not a valid host group id. Fix it in /config.');
  }
  return jsonResult({ ok: true, device_id: a.aid, playbook: irPlaybookText(a.aid, quarantineGroupId) });
}

export function renderShadowAiPlaybook(input: Record<string, unknown>, bannedGroupId: string | undefined): EyasToolResult {
  const a = checkAid(input);
  if ("error" in a) return a.error;
  if (!bannedGroupId) {
    return fail(
      'The active environment\'s "Shadow-AI banned host group" is not set. Configure it on the ' +
        "active environment in /config (it must be the id of a static Falcon Host Group bound to a " +
        "Shadow-AI prevention policy) before running this workflow.",
    );
  }
  if (!GROUP_ID_RX.test(bannedGroupId)) {
    return fail('The active environment\'s "Shadow-AI banned host group" id is not a valid host group id. Fix it in /config.');
  }
  return jsonResult({ ok: true, device_id: a.aid, playbook: shadowAiPlaybookText(a.aid, bannedGroupId) });
}

export function renderIdentityIrPlaybook(input: Record<string, unknown>): EyasToolResult {
  const entityId = str(input.entity_id);
  const sam = str(input.sam_account_name);
  if (!entityId && !sam) {
    return fail("Identity IR workflow requires an entity_id or sam_account_name.");
  }
  if (entityId && !ENTITY_ID_RX.test(entityId)) {
    return fail("entity_id may contain only letters, digits and hyphens.");
  }
  if (sam && !SAM_RX.test(sam)) {
    return fail("sam_account_name may contain only letters, digits, spaces and . _ @ $ ' -");
  }
  const handle = entityId ?? sam ?? "(unknown)";
  const text = identityIrPlaybookText(
    handle,
    entityId ?? "(resolve from samAccountName)",
    sam ?? "(resolve from entity)",
  );
  return jsonResult({ ok: true, playbook: text });
}

export function renderDataProtectionPlaybook(): EyasToolResult {
  return jsonResult({ ok: true, playbook: dataProtectionPlaybookText() });
}
