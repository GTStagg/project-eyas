import type { EyasTool } from "./types";
import { PLAYBOOK_TOOLS } from "./playbook-tools";
import { RTR_TOOLS } from "./rtr-tools";
import { HOST_GROUP_TOOLS } from "./host-group-tools";
import { QUARANTINE_TOOLS } from "./quarantine-tools";
import { TEARDOWN_TOOLS } from "./teardown-tools";
import { IR_TOOLS } from "./ir-tools";
import { IR_HOST_TOOLS } from "./ir-host-tools";
import { SHADOW_AI_TOOLS } from "./shadow-ai-tools";
import { TUNING_TOOLS } from "./tuning-tools";

export type { EyasTool, EyasToolContext, EyasToolResult } from "./types";

// Every tool Eyas serves in-process. The bridge lists these alongside
// eyas-mcp's natives, and they win over a sidecar tool of the same name.
export const EYAS_TOOLS: readonly EyasTool[] = [
  ...PLAYBOOK_TOOLS,
  ...RTR_TOOLS,
  ...HOST_GROUP_TOOLS,
  ...QUARANTINE_TOOLS,
  ...TEARDOWN_TOOLS,
  ...IR_TOOLS,
  ...IR_HOST_TOOLS,
  ...SHADOW_AI_TOOLS,
  ...TUNING_TOOLS,
];

export const EYAS_TOOL_MAP: ReadonlyMap<string, EyasTool> = new Map(
  EYAS_TOOLS.map((t) => [t.name, t]),
);
