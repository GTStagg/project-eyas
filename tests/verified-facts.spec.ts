import { test, expect } from "@playwright/test";

// Client-render coverage for the "Verified by Eyas — independent of the agent"
// approval-card block (S4 / F1 / F4 / F5). The server computes a `verified`
// payload from the IR ground-truth tables (containment provenance, host role,
// release caveat) and attaches it to the `tool_pending_approval` SSE event; the
// route's IR-aware guard backstops the actual writes. Driving that end to end
// needs a live host AID + Falcon scope, so the *server* half is unit-tested
// (ir-ground-truth 31/31, ir-eligibility, approvals). This spec pins the *client*
// half deterministically: given a pending-approval event carrying `verified`,
// VerifiedFacts renders the right operator-plain copy with the right emphasis.
//
// We stub /api/chat with a hand-crafted SSE body (same pattern as
// phase0-receipts.spec.ts) so the test never touches Falcon/Anthropic. Two
// pending tools exercise both verified shapes:
//   * falcon_lift_host_containment — DC blast-radius warning + "already contained
//     before this investigation began" provenance (agentContained=false,
//     containedAtStart=true) + the detection-status release caveat.
//   * extras_host_group_remove_members — "membership predates this engagement"
//     provenance (workflowAddedToGroup=false) + the same caveat.

const AID = "abad1deaabad1deaabad1deaabad1dea";
const GID = "env_quarantine_group_01";
const RELEASE_NOTE =
  "Release readiness is judged from detection status, not re-scanned artifacts. Eyas may decline a release but never auto-releases this host and never overrides the Falcon Console.";

function ssePayload(): string {
  const blocks = [
    `event: ready\ndata: {}\n\n`,
    `event: iteration_start\ndata: ${JSON.stringify({ iteration: 0 })}\n\n`,
    `event: text\ndata: Phase 4 — proposing release actions. Each write is gated; review the verified facts before approving.\n\n`,
    // Lift containment — emit tool_use then tool_pending_approval (the real
    // agent-loop order: agent-loop.ts:326 then :422).
    `event: tool_use\ndata: ${JSON.stringify({
      id: "tu-lift",
      name: "falcon_lift_host_containment",
      input: { ids: [AID] },
    })}\n\n`,
    `event: tool_pending_approval\ndata: ${JSON.stringify({
      id: "tu-lift",
      name: "falcon_lift_host_containment",
      input: { ids: [AID] },
      verified: {
        hostRole: "Domain Controller",
        isDomainController: true,
        agentContained: false,
        containedAtStart: true,
        releaseVerificationNote: RELEASE_NOTE,
      },
    })}\n\n`,
    // Group remove — same two-event order.
    `event: tool_use\ndata: ${JSON.stringify({
      id: "tu-remove",
      name: "extras_host_group_remove_members",
      input: { device_ids: [AID], group_id: GID },
    })}\n\n`,
    `event: tool_pending_approval\ndata: ${JSON.stringify({
      id: "tu-remove",
      name: "extras_host_group_remove_members",
      input: { device_ids: [AID], group_id: GID },
      verified: {
        workflowAddedToGroup: false,
        releaseVerificationNote: RELEASE_NOTE,
      },
    })}\n\n`,
    // No `done` event: a real pending approval pauses the stream open while the
    // operator decides. The card stays rendered after the stub body is consumed.
  ];
  return blocks.join("");
}

test("approval cards render the Verified-by-Eyas block with provenance + blast-radius copy", async ({
  page,
}) => {
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

  const input = page.getByPlaceholder(/Eyas/i).first();
  await expect(input).toBeVisible({ timeout: 30_000 });
  // sessionId hydration gates the "New chat" button enabling.
  await expect(page.getByRole("button", { name: /New chat/ })).toBeEnabled({
    timeout: 15_000,
  });
  await input.click();
  await page.keyboard.type("propose phase 4 release actions");
  await expect(input).toHaveValue(/release/);
  const sendBtn = page.getByRole("button", { name: /Send/ }).first();
  await expect(sendBtn).toBeEnabled({ timeout: 5_000 });
  await sendBtn.click();

  // Both pending-approval cards auto-expand (status === "pending" forces open),
  // so no header click is needed. The verified block header appears once per card.
  const verifiedHeaders = page.getByText(
    "Verified by Eyas — independent of the agent",
  );
  await expect(verifiedHeaders.first()).toBeVisible({ timeout: 15_000 });
  await expect(verifiedHeaders).toHaveCount(2);

  // ── Lift card: DC blast-radius + prior-containment provenance ──────────────
  await expect(page.getByText("Host role: Domain Controller")).toBeVisible();
  await expect(
    page.getByText(/This host is a Domain Controller\. Network containment cuts off sign-ins/),
  ).toBeVisible();
  await expect(
    page.getByText(/already contained before this investigation began — not by this workflow/),
  ).toBeVisible();

  // ── Group-remove card: membership-predates provenance ──────────────────────
  await expect(
    page.getByText(/did not place this host in the group it's being removed from/),
  ).toBeVisible();
  await expect(page.getByText(/Eyas will decline this removal/)).toBeVisible();

  // ── Release caveat (both cards): detection-status, never auto-release ───────
  await expect(page.getByText(/never auto-releases this host/).first()).toBeVisible();

  // Warn lines render red (the visual "stop and read" signal). The DC line is a
  // warn line; confirm it carries the red class so the emphasis isn't lost.
  const dcLine = page
    .getByText(/This host is a Domain Controller\. Network containment cuts off sign-ins/)
    .first();
  await expect(dcLine).toHaveClass(/text-red-300/);

  // The release caveat renders as a muted italic note, not a red warning.
  const note = page.getByText(/never auto-releases this host/).first();
  await expect(note).toHaveClass(/italic/);

  await page.screenshot({
    path: "tests/screenshots/verified-facts.png",
    fullPage: true,
  });
});
