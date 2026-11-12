import type { EyasTool } from "./types";
import { PLAYBOOK_TOOLS } from "./playbook-tools";
import { RTR_TOOLS } from "./rtr-tools";
import { HOST_GROUP_TOOLS } from "./host-group-tools";
import { QUARANTINE_TOOLS } from "./quarantine-tools";

export type { EyasTool, EyasToolContext, EyasToolResult } from "./types";

// Every tool Eyas serves in-process. The bridge lists these alongside
// eyas-mcp's natives, and they win over a sidecar tool of the same name.
export const EYAS_TOOLS: readonly EyasTool[] = [
  ...PLAYBOOK_TOOLS,
  ...RTR_TOOLS,
  ...HOST_GROUP_TOOLS,
  ...QUARANTINE_TOOLS,
];

export const EYAS_TOOL_MAP: ReadonlyMap<string, EyasTool> = new Map(
  EYAS_TOOLS.map((t) => [t.name, t]),
);
