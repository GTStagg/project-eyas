import "server-only";

export type WebhookPayload = {
  title: string;
  source: string;
  markdown: string;
};

export type WebhookResult =
  | { ok: true; status: number; chunks: number }
  | { ok: false; status: number; error: string };

const MAX_MARKDOWN = 200_000;

export function getOutboundWebhookUrl(): string | null {
  const url = process.env.OUTBOUND_WEBHOOK_URL?.trim();
  if (!url) return null;
  if (!/^https?:\/\//i.test(url)) return null;
  return url;
}

export async function deliverToWebhook(p: WebhookPayload): Promise<WebhookResult> {
  const url = getOutboundWebhookUrl();
  if (!url) return { ok: false, status: 503, error: "OUTBOUND_WEBHOOK_URL is not configured." };

  const title = p.title.slice(0, 200);
  const source = p.source.slice(0, 100);
  const timestamp = new Date().toISOString();
  const markdown = p.markdown.slice(0, MAX_MARKDOWN);

  const isDiscord =
    /^https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\//i.test(url);

  try {
    return isDiscord
      ? await deliverDiscord(url, { title, source, timestamp, markdown })
      : await deliverGeneric(url, { title, source, timestamp, markdown });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { ok: false, status: 0, error: `Webhook delivery failed: ${msg}` };
  }
}

type Internal = WebhookPayload & { timestamp: string };

async function deliverGeneric(url: string, p: Internal): Promise<WebhookResult> {
  const resp = await postJson(url, {
    title: p.title,
    source: p.source,
    timestamp: p.timestamp,
    markdown: p.markdown,
    text: p.markdown,
  });
  if (!resp.ok) return { ok: false, status: resp.status, error: `HTTP ${resp.status}` };
  return { ok: true, status: resp.status, chunks: 1 };
}

// Discord rate-limits webhooks aggressively (per-webhook + global buckets),
// especially when we post a multi-chunk briefing as several messages
// back-to-back. A 429 carries the wait in `retry_after` (seconds, JSON body)
// and the `Retry-After` header. Honor it with a bounded retry instead of
// failing the whole delivery on the first throttle.
const DISCORD_MAX_RETRIES = 3;
const DISCORD_MAX_BACKOFF_MS = 10_000;

async function retryAfterMs(resp: Response): Promise<number> {
  // Prefer the JSON body's retry_after (Discord-specific, fractional seconds);
  // fall back to the standard Retry-After header. Default to a small backoff.
  try {
    const body = (await resp.clone().json()) as { retry_after?: number };
    if (typeof body.retry_after === "number" && body.retry_after >= 0) {
      return Math.min(Math.ceil(body.retry_after * 1000), DISCORD_MAX_BACKOFF_MS);
    }
  } catch {
    /* not JSON — fall through to header */
  }
  const header = resp.headers.get("retry-after");
  const secs = header ? Number(header) : NaN;
  if (Number.isFinite(secs) && secs >= 0) {
    return Math.min(Math.ceil(secs * 1000), DISCORD_MAX_BACKOFF_MS);
  }
  return 1_000;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function deliverDiscord(url: string, p: Internal): Promise<WebhookResult> {
  const header = `**${p.title}** — _${p.source} · ${p.timestamp}_`;
  const chunks = splitForDiscord(p.markdown, 1900);
  const messages = chunks.map((chunk, i) => (i === 0 ? `${header}\n\n${chunk}` : chunk));

  let lastStatus = 0;
  for (const content of messages) {
    let resp: Response | null = null;
    for (let attempt = 0; attempt <= DISCORD_MAX_RETRIES; attempt++) {
      resp = await postJson(url, { content, allowed_mentions: { parse: [] } });
      if (resp.status !== 429) break;
      if (attempt === DISCORD_MAX_RETRIES) {
        return {
          ok: false,
          status: 429,
          error: `Discord rate-limited after ${DISCORD_MAX_RETRIES + 1} attempts`,
        };
      }
      await sleep(await retryAfterMs(resp));
    }
    // resp is non-null here (loop runs at least once).
    lastStatus = resp!.status;
    if (!resp!.ok) return { ok: false, status: resp!.status, error: `Discord HTTP ${resp!.status}` };
  }
  return { ok: true, status: lastStatus, chunks: messages.length };
}

export function splitForDiscord(text: string, max: number): string[] {
  if (text.length <= max) return [text];
  const out: string[] = [];
  const lines = text.split("\n");
  let buf = "";
  for (const line of lines) {
    const candidate = buf ? `${buf}\n${line}` : line;
    if (candidate.length <= max) {
      buf = candidate;
      continue;
    }
    if (buf) out.push(buf);
    if (line.length <= max) {
      buf = line;
    } else {
      for (let i = 0; i < line.length; i += max) {
        const piece = line.slice(i, i + max);
        if (i + max >= line.length) {
          buf = piece;
        } else {
          out.push(piece);
        }
      }
    }
  }
  if (buf) out.push(buf);
  return out;
}

async function postJson(url: string, body: unknown) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10_000);
  try {
    return await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }
}
