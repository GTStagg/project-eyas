import { NextResponse, type NextRequest } from "next/server";
import { getRuntimeConfig, saveRuntimeConfig } from "@/lib/config/runtime";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Surfaces the active environment's Shadow-AI configuration to the panel:
//   - bannedGroupId   — host group id targeted by Ban+Clean (32-char hex)
//   - sanctionedTools — operator-curated allow list (catalog tool ids)
//
// Reads through the settings store (`getRuntimeConfig`) so a `.env` value
// still works on first boot — the store's migration synthesizes it into
// the active environment record on first read; once /status saves a value,
// settings.json is the authority.
export async function GET() {
  const cfg = getRuntimeConfig();
  const raw = (cfg.shadowAiBannedGroupId || "").trim();
  // Falcon group ids are 32-char hex; refuse anything else so a typo
  // doesn't land in the primer.
  const valid = /^[a-fA-F0-9]{32}$/.test(raw);
  return NextResponse.json({
    ok: true,
    bannedGroupId: valid ? raw : null,
    configured: valid,
    sanctionedTools: cfg.shadowAiSanctionedTools,
  });
}

// Mutates the sanctioned-tools list on the active environment.
// Two shapes accepted (mirrors the typical UI flows):
//   - { tool: "github-copilot", sanctioned: true|false } — toggle one
//   - { tools: ["...","..."] }                          — replace whole list
//
// Tool ids are normalized lowercase + deduped server-side. The active
// environment's record is the storage location; switching environments
// shows a different list (sanctioning is tenant-scoped by design).
export async function POST(request: NextRequest) {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ ok: false, error: "invalid JSON" }, { status: 400 });
  }
  if (!body || typeof body !== "object") {
    return NextResponse.json({ ok: false, error: "expected object" }, { status: 400 });
  }
  const b = body as { tool?: unknown; sanctioned?: unknown; tools?: unknown };

  const current = getRuntimeConfig().shadowAiSanctionedTools;
  let next: string[];

  if (Array.isArray(b.tools)) {
    next = b.tools.filter((v): v is string => typeof v === "string");
  } else if (typeof b.tool === "string") {
    const tool = b.tool.trim().toLowerCase();
    if (!tool) {
      return NextResponse.json({ ok: false, error: "tool must be non-empty" }, { status: 400 });
    }
    const set = new Set(current);
    if (b.sanctioned === false) set.delete(tool);
    else set.add(tool);
    next = [...set];
  } else {
    return NextResponse.json(
      { ok: false, error: "expected { tool, sanctioned } or { tools: [] }" },
      { status: 400 },
    );
  }

  await saveRuntimeConfig({ shadowAiSanctionedTools: next });
  return NextResponse.json({
    ok: true,
    sanctionedTools: getRuntimeConfig().shadowAiSanctionedTools,
  });
}
