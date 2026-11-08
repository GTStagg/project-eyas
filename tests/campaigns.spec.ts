import { test, expect } from "@playwright/test";

test("Cross-host campaigns panel renders when tenant has clusters", async ({ page }) => {
  const consoleErrors: string[] = [];
  page.on("console", (msg) => {
    if (msg.type() === "error") consoleErrors.push(msg.text());
  });
  page.on("pageerror", (err) => consoleErrors.push(`pageerror: ${err.message}`));

  // Probe the API first to see whether the current tenant has any campaigns.
  // The panel only renders when campaigns.length > 0; on a clean tenant the
  // assertion would correctly skip rather than fail. Longer timeout because
  // /api/queue includes server-side identity-overlay enrichment that
  // serializes through MCP (~15s cold).
  const apiResp = await page.request.get("/api/queue", { timeout: 60_000 });
  const apiJson = await apiResp.json();
  const campaigns = (apiJson?.campaigns ?? []) as unknown[];

  await page.goto("/queue", { waitUntil: "networkidle" });
  await expect(page.getByText(/^total$/)).toBeVisible({ timeout: 30_000 });

  if (campaigns.length === 0) {
    test.skip(true, "Tenant has no cross-host campaigns — nothing to assert.");
  }

  // Section heading renders.
  await expect(page.getByText(/cross-host \/\/ campaigns/i)).toBeVisible();

  // At least one Reconstruct hand-off button exists.
  const reconstruct = page.getByRole("button", { name: /^Reconstruct$/ });
  expect(await reconstruct.count()).toBeGreaterThan(0);

  // Clicking Reconstruct primes the chat. Assert URL gets a primer query.
  await reconstruct.first().click();
  await page.waitForURL(/\?primer=/, { timeout: 5_000 });

  expect(consoleErrors.filter((e) => !e.includes("caret-color"))).toEqual([]);
});
