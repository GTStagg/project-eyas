import "server-only";
import { AIGuard } from "@crowdstrike/aidr";
import { getActiveAidrCredential } from "@/lib/config/environments";
import { getActiveEnvironmentId } from "@/lib/config/environments";
import { db, rawDb } from "@/lib/db/client";
import { aidrBlocks } from "@/lib/db/schema";
import crypto from "node:crypto";

// CrowdStrike AI Detection and Response (AIDR) integration. Hosted
// guardrail service —
// scans LLM input/output for prompt injection, PII, jailbreaks, malicious
// entities, etc. We call it as a pre-loop input gate and a post-loop output
// gate on the chat surface only. Other surfaces (IR/triage/investigate) are
// scoped out for v1.
//
// Per-environment credential: each environment row carries its own token +
// base URL (stored encrypted in the DB via lib/db/crypto.ts). Missing token
// = AIDR disabled for that env; callers branch on isAidrEnabled() and
// gracefully bypass.
//
// The SDK's baseURLTemplate substitutes {SERVICE_NAME} for "aiguard". Users
// paste the literal URL CrowdStrike shows them in the collector install
// section (e.g. https://api.crowdstrike.com/aidr/aiguard); we convert to
// the template form at the boundary so the SDK sees what it expects.

export type AidrEventType = "input" | "output";

export type AidrDetectorResult = {
  detected?: boolean;
  data?: unknown;
};

export type AidrVerdict = {
  blocked: boolean;
  transformed?: boolean;
  policy?: string;
  /** SDK envelope status: "Success" on a final result, "Accepted" when the
   *  request landed in the async queue (202+poll path). We surface this so
   *  callers can decide whether to wait or fail open. */
  status?: string;
  detectors?: Record<string, AidrDetectorResult | undefined>;
};

const SDK_PLACEHOLDER = "{SERVICE_NAME}";
const SERVICE_NAME = "aiguard";

/** Convert a user-pasted literal base URL into the template form the SDK
 *  expects. Idempotent: if the URL already contains {SERVICE_NAME}, returns
 *  unchanged. Trailing slashes are tolerated. */
function toTemplateUrl(literal: string): string {
  if (literal.includes(SDK_PLACEHOLDER)) return literal.replace(/\/+$/, "");
  const trimmed = literal.replace(/\/+$/, "");
  const suffix = `/${SERVICE_NAME}`;
  if (trimmed.toLowerCase().endsWith(suffix)) {
    return trimmed.slice(0, -suffix.length) + `/${SDK_PLACEHOLDER}`;
  }
  // No `/aiguard` suffix — assume the user gave us a host root and append.
  return `${trimmed}/${SDK_PLACEHOLDER}`;
}

export function isAidrEnabled(): boolean {
  return getActiveAidrCredential() !== null;
}

function newClient(token: string, baseUrl: string): AIGuard {
  return new AIGuard({
    token,
    baseURLTemplate: toTemplateUrl(baseUrl),
    // Block-on-violation is the hot path — keep latency tight. The SDK's
    // default 60s is the right cap for the 202+poll fallback on large
    // payloads but most calls complete sub-second.
    timeout: 60_000,
    maxRetries: 2,
  });
}

/** Scan a chat turn's input messages. Returns null when AIDR is not
 *  configured on the active environment (caller proceeds without gating). */
export async function scanInput(opts: {
  messages: Array<{ role: string; content: string }>;
  sessionId?: string;
}): Promise<AidrVerdict | null> {
  const cred = getActiveAidrCredential();
  if (!cred) return null;
  const client = newClient(cred.token, cred.baseUrl);
  const resp = await client.guardChatCompletions({
    guard_input: { messages: opts.messages },
    event_type: "input",
    app_id: "project-eyas",
    llm_provider: "anthropic",
  } as Parameters<typeof client.guardChatCompletions>[0]);
  const verdict = normalizeVerdict(resp);
  if (process.env.AIDR_DEBUG === "1") {
    console.log(
      `[aidr:input] blocked=${verdict.blocked} status=${verdict.status} policy=${verdict.policy ?? "—"} detectors=${blockedDetectors(verdict).join(",") || "—"}`,
    );
  }
  return verdict;
}

/** Scan an assistant-output text blob. Same semantics as scanInput. */
export async function scanOutput(opts: {
  text: string;
  sessionId?: string;
}): Promise<AidrVerdict | null> {
  const cred = getActiveAidrCredential();
  if (!cred) return null;
  const client = newClient(cred.token, cred.baseUrl);
  const resp = await client.guardChatCompletions({
    guard_input: {
      messages: [{ role: "assistant", content: opts.text }],
    },
    event_type: "output",
    app_id: "project-eyas",
    llm_provider: "anthropic",
  } as Parameters<typeof client.guardChatCompletions>[0]);
  const verdict = normalizeVerdict(resp);
  if (process.env.AIDR_DEBUG === "1") {
    console.log(
      `[aidr:output] blocked=${verdict.blocked} status=${verdict.status} policy=${verdict.policy ?? "—"} detectors=${blockedDetectors(verdict).join(",") || "—"}`,
    );
  }
  return verdict;
}

// Pangea-style envelope: { status, result, request_id, ... }. The SDK
// wraps every guardChatCompletions call so `blocked` and `detectors` live
// at resp.result.*, not resp.*. Earlier versions of this normalizer read
// the outer envelope and never saw a block — every gate was a silent
// no-op even when the underlying API returned a true positive.
function normalizeVerdict(resp: unknown): AidrVerdict {
  const env = (resp ?? {}) as Record<string, unknown>;
  const status = typeof env.status === "string" ? env.status : undefined;
  // Async 202: result is { ttl_mins, retry_counter, location } — no
  // verdict yet. Fail open and let the caller decide; polling support is
  // a follow-up if this turns out to be common for chat-size payloads.
  if (status === "Accepted") {
    return { blocked: false, status, transformed: false };
  }
  const result = (env.result ?? {}) as Record<string, unknown>;
  return {
    blocked: result.blocked === true,
    transformed: result.transformed === true,
    policy: typeof result.policy === "string" ? result.policy : undefined,
    status,
    detectors:
      result.detectors && typeof result.detectors === "object"
        ? (result.detectors as Record<string, AidrDetectorResult>)
        : undefined,
  };
}

/** Detector keys whose `detected: true` fired on a blocked verdict —
 *  used to render the chips on the block bubble and to feed the audit
 *  row. Real keys from the SDK: malicious_prompt, confidential_and_pii_entity,
 *  malicious_entity, custom_entity, secret_and_key_entity, competitors,
 *  language, topic, code. */
export function blockedDetectors(verdict: AidrVerdict): string[] {
  if (!verdict.detectors) return [];
  const out: string[] = [];
  for (const [key, det] of Object.entries(verdict.detectors)) {
    if (det && det.detected === true) out.push(key);
  }
  return out;
}

/** Append-only audit row. Best-effort — never throws. The preview hash is
 *  a sha256 of the scanned text (truncated to 16 hex chars) so we can
 *  correlate without storing the offending content. */
export function recordBlock(opts: {
  sessionId?: string;
  eventType: AidrEventType;
  verdict: AidrVerdict;
  textPreview: string;
}): void {
  try {
    const envId = getActiveEnvironmentId();
    const hash = crypto
      .createHash("sha256")
      .update(opts.textPreview, "utf8")
      .digest("hex")
      .slice(0, 16);
    const tx = rawDb().transaction(() => {
      db().insert(aidrBlocks).values({
        ts: new Date().toISOString(),
        envId,
        sessionId: opts.sessionId ?? null,
        eventType: opts.eventType,
        policy: opts.verdict.policy ?? null,
        // No display_message in the SDK response shape — the chat route
        // synthesizes operator-facing text from blockedDetectors() instead.
        displayMessage: null,
        detectorsJson: JSON.stringify(opts.verdict.detectors ?? {}),
        previewHash: hash,
      }).run();
    });
    tx();
  } catch (err) {
    console.warn("[aidr] recordBlock failed:", (err as Error).message);
  }
}
