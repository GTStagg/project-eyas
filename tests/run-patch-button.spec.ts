import { test, expect } from "@playwright/test";

test("Run patch link surfaces a primer on /vulnerabilities by-patch row", async ({ page }) => {
  // /vulnerabilities does heavy server-side fan-out (~50s cold on a 200-host
  // fleet); networkidle's 15s default never settles. domcontentloaded + an
  // explicit wait for the By-patch button to be ready is the right shape.
  await page.goto("/vulnerabilities", { waitUntil: "domcontentloaded", timeout: 90_000 });
  await page.getByRole("button", { name: /By patch/ }).click({ timeout: 90_000 });
  await page.waitForSelector("text=/Update /", { timeout: 60_000 });
  await page.locator("tr.cursor-pointer").first().click();

  // "Run patch in chat" is a <button> that navigates via window.location.
  // Plan resolution can lag (sidecar resolves vendor/product → script id);
  // give it longer than expect's 8s default.
  const btn = page.getByRole("button", { name: /Run patch in chat/ });
  await expect(btn).toBeVisible({ timeout: 30_000 });
  await btn.click();

  // Click navigates to /?primer=...; assert URL + decode the primer.
  // handleRunInChat awaits ensureVerifiedHosts() (Falcon host lookup) before
  // navigating; that can take 30+ seconds on a cold sidecar.
  await page.waitForURL(/\?primer=/, { timeout: 60_000 });
  const url = new URL(page.url());
  const primer = url.searchParams.get("primer") ?? "";
  console.log("[probe] primer length:", primer.length);
  console.log("[probe] primer first 240:", primer.slice(0, 240));
  expect(primer).toMatch(/^Patch /);
  expect(primer).toContain("curated RTR script library");
  expect(primer).toMatch(/host[s]?:/);
});
