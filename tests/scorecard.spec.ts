import { test, expect } from "@playwright/test";

// /scorecard renders three deterministic sections from pure local-DB reads (no
// upstream Falcon calls), all scoped to the active environment. This spec
// asserts user-VISIBLE output, not derived metadata: the activity surface bars
// with non-zero run counts, a posture-movement headline row, and the operations
// section (empty state here — the local DB has cost_log + posture rows for the
// active env but no IR engagements). Assumes >=1 cost_log row and >=2 posture
// snapshots already exist for the active env in data/eyas.db.
test("scorecard renders all three sections with visible env-scoped output", async ({ page }) => {
  const consoleErrors: string[] = [];
  page.on("console", (msg) => {
    if (msg.type() === "error") consoleErrors.push(msg.text());
  });
  page.on("pageerror", (err) => consoleErrors.push(`pageerror: ${err.message}`));

  await page.goto("/scorecard", { waitUntil: "domcontentloaded", timeout: 60_000 });

  // The three section headings all render.
  await expect(page.getByRole("heading", { name: "Agentic operations" })).toBeVisible({
    timeout: 30_000,
  });
  await expect(page.getByRole("heading", { name: "Agentic activity" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Posture movement" })).toBeVisible();

  // Operations: no IR engagements for this env yet -> the empty-state copy,
  // never a thrown error or a blank section.
  await expect(
    page.getByText("No incident-response engagements yet", { exact: true }),
  ).toBeVisible();

  // Activity: populated. Scope to the section so the "Chat" surface label can't
  // collide with the "Chat" nav link in the AppShell sidebar.
  const activity = page
    .locator("section")
    .filter({ has: page.getByRole("heading", { name: "Agentic activity" }) });

  // "Workflows run" stat card is present with a positive total.
  await expect(activity.getByText("Workflows run", { exact: true })).toBeVisible();

  // The per-surface list shows the "Chat" row with a visible, positive run count
  // (the count div is a sibling of the label div within the same row).
  const chatRow = activity.getByText("Chat", { exact: true }).locator("..");
  await expect(chatRow).toBeVisible();
  const chatText = await chatRow.innerText();
  const chatMatch = chatText.match(/(\d+)/);
  expect(chatMatch).not.toBeNull();
  expect(Number(chatMatch![1])).toBeGreaterThan(0);

  // Posture: populated (>=2 snapshots), so at least the "Open detections"
  // headline row renders (not the "appears after the second capture" empty state).
  const posture = page
    .locator("section")
    .filter({ has: page.getByRole("heading", { name: "Posture movement" }) });
  await expect(posture.getByText("Open detections", { exact: true })).toBeVisible();

  expect(consoleErrors).toEqual([]);
});
