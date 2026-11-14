// The text blocks of an MCP tool result, joined. Non-text blocks become empty
// strings. A missing `content` throws on purpose: a failed call must not read
// as an empty success.
export type McpContent = Array<{ type: string; text?: string }>;

export function mcpText(content: unknown, separator = "\n"): string {
  return (content as McpContent)
    .map((c) => (c.type === "text" && c.text ? c.text : ""))
    .join(separator);
}
