import { test, expect } from "@playwright/test";

// Verifies the new operator-visible receipt strip that renders below the
// tool name on collapsed tool-call bubbles when the server emits a `summary`
// field on a `tool_result` SSE event.
//
// We stub /api/chat with a hand-crafted SSE body so the test is deterministic
// and doesn't depend on Falcon/Anthropic. The three synthetic tool_result
// events carry summaries that mirror what summarizeToolResult() produces for
// real Phase 0 prefetch payloads.

function ssePayload(): string {
  const blocks = [
    `event: ready\ndata: {}\n\n`,
    `event: iteration_start\ndata: ${JSON.stringify({ iteration: 0 })}\n\n`,
    `event: text\ndata: Loading IR playbook, capturing campaign scope, and partitioning open detections for actionability…\n\n`,
    `event: tool_use\ndata: ${JSON.stringify({
      id: "tu-playbook",
      name: "extras_ir_workflow_playbook",
      input: { device_id: "FAKE-AID-123" },
    })}\n\n`,
    `event: tool_use\ndata: ${JSON.stringify({
      id: "tu-scope",
      name: "extras_ir_campaign_scope",
      input: { device_id: "FAKE-AID-123" },
    })}\n\n`,
    `event: tool_use\ndata: ${JSON.stringify({
      id: "tu-actionable",
      name: "extras_ir_phase0_actionable_check",
      input: { device_id: "FAKE-AID-123" },
    })}\n\n`,
    `event: tool_result\ndata: ${JSON.stringify({
      tool_use_id: "tu-playbook",
      content: '{"ok":true}',
      is_error: false,
      duration_ms: 47,
      summary: "playbook loaded",
    })}\n\n`,
    `event: tool_result\ndata: ${JSON.stringify({
      tool_use_id: "tu-actionable",
      content: '{"ok":true}',
      is_error: false,
      duration_ms: 980,
      summary: "3 actionable · 9 noise · 12 total",
    })}\n\n`,
    `event: tool_result\ndata: ${JSON.stringify({
      tool_use_id: "tu-scope",
      content: '{"ok":true}',
      is_error: false,
      duration_ms: 6840,
      summary: "3 campaigns · 12 open detections · primary: drive_by",
    })}\n\n`,
    `event: text\ndata: Phase 0 enrichment complete.\n\n`,
    `event: done\ndata: ${JSON.stringify({ iterations: 1, usage: { input_tokens: 100, output_tokens: 50 } })}\n\n`,
  ];
  return blocks.join("");
}

test("Phase 0 prefetch tool bubbles render the operator receipt strip", async ({ page }) => {
  await page.route("**/api/chat", async (route) => {
    if (route.request().method() !== "POST") {
      await route.continue();
      return;
    }
    await route.fulfill({
      status: 200,
      headers: {
        "content-type": "text/event-stream",
        "cache-control": "no-cache, no-transform",
      },
      body: ssePayload(),
    });
  });

  await page.goto("/", { waitUntil: "domcontentloaded", timeout: 30_000 });

  // Submit any message — content is irrelevant because /api/chat is stubbed.
  const input = page.getByPlaceholder(/Eyas/i).first();
  await expect(input).toBeVisible({ timeout: 30_000 });
  // Wait for sessionId hydration (the "New chat" button is enabled once
  // sessionId is set; that lets us also confirm the chat is hydrated before
  // typing).
  await expect(page.getByRole("button", { name: /New chat/ })).toBeEnabled({
    timeout: 15_000,
  });
  await input.click();
  await page.keyboard.type("trigger phase 0 receipt test");
  // Sanity-check the value reached React state.
  await expect(input).toHaveValue(/trigger/);
  const sendBtn = page.getByRole("button", { name: /Send/ }).first();
  await expect(sendBtn).toBeEnabled({ timeout: 5_000 });
  await sendBtn.click();

  // Wait for the assistant turn to settle. Tool bubbles auto-collapse to a
  // "3 tool calls" header once the turn finishes; click "show" to expand them
  // so the receipt strips render.
  const collapsedHeader = page.getByText(/3 tool calls/).first();
  await expect(collapsedHeader).toBeVisible({ timeout: 15_000 });
  await collapsedHeader.click();
  await expect(page.getByText("playbook loaded", { exact: false })).toBeVisible({ timeout: 5_000 });
  await expect(
    page.getByText(/3 campaigns .* 12 open detections .* primary: drive_by/),
  ).toBeVisible({ timeout: 5_000 });
  await expect(
    page.getByText(/3 actionable .* 9 noise .* 12 total/),
  ).toBeVisible({ timeout: 5_000 });

  // Visible affordance: the receipt strip starts with a ↳ glyph.
  const arrows = page.locator("text=↳");
  await expect(arrows.first()).toBeVisible({ timeout: 5_000 });

  // Capture a screenshot for the artifact directory.
  await page.screenshot({
    path: "tests/screenshots/phase0-receipts.png",
    fullPage: true,
  });
});
