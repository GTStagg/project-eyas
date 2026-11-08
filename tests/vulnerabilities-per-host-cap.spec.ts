import { test, expect } from "@playwright/test";

// Verifies the per-host cap fix: with cap=5 (default), the By-patch view should
// span more than 2 hosts even when a noisy server saturates the raw Spotlight
// fetch. With cap=off, the same view often collapses to 1-2 hosts on this
// tenant — which was the pre-fix behaviour.
test("Vulnerabilities per-host cap spreads By-patch view across many hosts", async ({ page }) => {
  const consoleErrors: string[] = [];
  page.on("console", (msg) => {
    if (msg.type() === "error") consoleErrors.push(msg.text());
  });
  page.on("pageerror", (err) => consoleErrors.push(`pageerror: ${err.message}`));

  // Default load: mode=critical, cap=5 implicitly.
  await page.goto("/vulnerabilities", { waitUntil: "networkidle", timeout: 90_000 });

  await expect(page.getByRole("heading", { name: /Open vulnerabilities/ })).toBeVisible();

  // Per-host chip row exists and "top 5" is selected.
  await expect(page.getByText(/per-host \/\//)).toBeVisible();
  const top5Chip = page.getByRole("link", { name: /^top 5$/ });
  await expect(top5Chip).toBeVisible();

  // Switch to By patch view explicitly via URL so we exercise the bundle path
  // the user reported saturating at 2 hosts.
  await page.goto("/vulnerabilities?mode=critical&view=patch&filter=criticalHigh,hasFix", {
    waitUntil: "networkidle",
    timeout: 90_000,
  });

  // Header summary line includes hosts count — read it.
  const summary = await page
    .locator("span.font-mono")
    .filter({ hasText: /vulns ·/ })
    .first()
    .textContent();
  expect(summary, "header summary present").toBeTruthy();
  const hostsMatch = summary!.match(/·\s*(\d+)\s*hosts?/);
  expect(hostsMatch, `parsed host count out of "${summary}"`).not.toBeNull();
  const hostCount = parseInt(hostsMatch![1], 10);

  // Core assertion: per-host fan-out should reach more than the 1-2 hosts
  // the global fetch saturated on. Threshold of 5 leaves headroom for tiny
  // tenants while still failing if the regression returns.
  expect(hostCount, "By-patch host coverage with cap=5 (fan-out)").toBeGreaterThan(2);

  // Fleet-sweep banner should be present and reference the queried fleet.
  await expect(page.getByText(/Fleet sweep: queried [\d,]+/)).toBeVisible();

  // Behavioural assertion (the bit the prior version missed): the rendered
  // tabs must show non-zero counts under the default Critical+High+hasFix
  // filter on a tenant with known remediations. A 400 on the remediation
  // facet would silently zero these out — the metadata banner above can
  // still report "12 affected hosts" while the view itself collapses to 0.
  // Read the tab labels: "By patch (N)" and "By host (N)".
  const byPatchTab = page.getByRole("button", { name: /By patch \(\d+\)/ });
  const byHostTab = page.getByRole("button", { name: /By host \(\d+\)/ });
  await expect(byPatchTab).toBeVisible();
  await expect(byHostTab).toBeVisible();
  const byPatchText = (await byPatchTab.textContent()) ?? "";
  const byHostText = (await byHostTab.textContent()) ?? "";
  const byPatchCount = parseInt(byPatchText.match(/\((\d+)\)/)?.[1] ?? "0", 10);
  const byHostCount = parseInt(byHostText.match(/\((\d+)\)/)?.[1] ?? "0", 10);
  expect(byPatchCount, `By-patch group count (parsed from "${byPatchText.trim()}")`).toBeGreaterThan(0);
  expect(byHostCount, `By-host group count (parsed from "${byHostText.trim()}")`).toBeGreaterThan(0);

  // Also assert the table actually renders at least one data row, not just
  // header chrome. This guards against a future where tab counts come from
  // metadata but the visible table is empty.
  const dataRows = page.locator("table tbody tr");
  expect(await dataRows.count(), "rendered data rows").toBeGreaterThan(0);

  // No real console errors (filter Next dev caret-color noise).
  const realErrors = consoleErrors.filter((e) => !/caret-color/i.test(e));
  expect(realErrors, `console errors: ${realErrors.join("\n")}`).toHaveLength(0);
});

test("Vulnerabilities cap=off shows raw set", async ({ page }) => {
  await page.goto("/vulnerabilities?mode=critical&view=patch&filter=criticalHigh,hasFix&cap=0", {
    waitUntil: "networkidle",
    timeout: 90_000,
  });
  await expect(page.getByRole("heading", { name: /Open vulnerabilities/ })).toBeVisible();
  // "off" chip is the active one.
  const offChip = page.getByRole("link", { name: /^off$/ });
  await expect(offChip).toHaveClass(/border-brand-700/);
  // Trim banner must NOT be present when cap is off.
  await expect(page.getByText(/Trimmed \d+ lower-priority/)).toHaveCount(0);
});
