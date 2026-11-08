import { test, expect } from "@playwright/test";

test("Queue page renders ranked detections with hand-off buttons", async ({ page }) => {
  const consoleErrors: string[] = [];
  page.on("console", (msg) => {
    if (msg.type() === "error") consoleErrors.push(msg.text());
  });
  page.on("pageerror", (err) => consoleErrors.push(`pageerror: ${err.message}`));

  await page.goto("/queue", { waitUntil: "networkidle" });

  // Heading renders.
  await expect(page.getByRole("heading", { name: /Triage queue/ })).toBeVisible();

  // Stats bar populated (data loaded). Cold-cache load includes server-side
  // identity-overlay enrichment which serializes through MCP and can take
  // ~15s on a fresh server; bump the timeout to absorb that.
  await expect(page.getByText(/^total$/)).toBeVisible({ timeout: 30_000 });

  // At least one of the bucket sections renders.
  await expect(page.getByText("Top priorities").first()).toBeVisible();
  await expect(page.getByText("Active queue").first()).toBeVisible();

  // At least one per-row Triage button exists (current tenant has open detections).
  // Match exactly "Triage" (not "Generate triage" from the Brief panel above).
  const triageButtons = page.getByRole("button", { name: /^Triage$/ });
  expect(await triageButtons.count()).toBeGreaterThan(0);

  // Brief panel renders above the queue.
  await expect(page.getByRole("button", { name: /Generate triage/ })).toBeVisible();

  expect(consoleErrors.filter((e) => !e.includes("caret-color"))).toEqual([]);
});
