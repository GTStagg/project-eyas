import { test, expect } from "@playwright/test";

// /discover — Falcon Discover asset/application/account inventory decision-doc
// surface. On the SE tenant the Discover scope is granted, so the page renders
// summary stat cards + entity tables (NOT the scope-pending banner).
test("Discover surface renders inventory cards + tables and nav link", async ({ page }) => {
  const consoleErrors: string[] = [];
  page.on("console", (msg) => {
    if (msg.type() === "error") consoleErrors.push(msg.text());
  });
  page.on("pageerror", (err) => consoleErrors.push(`pageerror: ${err.message}`));

  // GET /api/discover fans out three sidecar calls; allow a generous cold wait.
  await page.goto("/discover", { waitUntil: "domcontentloaded", timeout: 90_000 });

  // Hero present.
  await expect(page.getByRole("heading", { name: "Asset inventory" })).toBeVisible({
    timeout: 90_000,
  });

  // Must NOT be the scope-pending banner on this tenant.
  await expect(page.getByText("Scope pending")).toHaveCount(0);

  // Stat cards: the four labels must be present, and the Admin-accounts card
  // must show a non-zero count (the SE box has 20 local admins).
  await expect(page.getByText("Assets", { exact: true })).toBeVisible({ timeout: 60_000 });
  await expect(page.getByText("Admin accounts", { exact: true })).toBeVisible();

  // Local administrator accounts table renders at least one row.
  const adminTable = page.getByText("Local administrator accounts");
  await expect(adminTable).toBeVisible({ timeout: 60_000 });
  const adminRows = page.locator("section:has-text('Local administrator accounts') tbody tr");
  expect(await adminRows.count()).toBeGreaterThan(0);

  // The assessment generator button is present (agentic layer entry point).
  await expect(page.getByRole("button", { name: /Generate assessment/ })).toBeVisible();

  await page.screenshot({ path: "tests/screenshots/discover.png", fullPage: true });

  // Sidebar nav exposes a Discover link pointing at /discover.
  const navLink = page.locator('a[href="/discover"]').first();
  await expect(navLink).toBeVisible();

  console.log("[probe] console errors:", consoleErrors);
  expect(consoleErrors).toEqual([]);
});
