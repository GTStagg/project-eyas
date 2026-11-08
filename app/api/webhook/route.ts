import { NextResponse } from "next/server";
import { deliverToWebhook, getOutboundWebhookUrl } from "@/lib/webhook/deliver";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  return NextResponse.json({ configured: getOutboundWebhookUrl() !== null });
}

export async function POST(req: Request) {
  if (!getOutboundWebhookUrl()) {
    return NextResponse.json(
      { ok: false, error: "OUTBOUND_WEBHOOK_URL is not configured." },
      { status: 503 },
    );
  }

  let body: { title?: string; markdown?: string; source?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ ok: false, error: "Invalid JSON body." }, { status: 400 });
  }

  const markdown = (body.markdown ?? "").toString();
  if (!markdown.trim()) {
    return NextResponse.json({ ok: false, error: "Empty markdown." }, { status: 400 });
  }

  const result = await deliverToWebhook({
    title: (body.title ?? "Falcon agent output").toString(),
    source: (body.source ?? "project-eyas").toString(),
    markdown,
  });

  if (!result.ok) {
    return NextResponse.json(
      { ok: false, error: result.error },
      { status: 502 },
    );
  }
  return NextResponse.json({ ok: true, status: result.status, chunks: result.chunks });
}
