import { test, expect } from "@playwright/test";

test("By-patch view exposes Build patch plan button", async ({ page }) => {
  const consoleErrors: string[] = [];
  page.on("console", (msg) => {
    if (msg.type() === "error") consoleErrors.push(msg.text());
  });
  page.on("pageerror", (err) => consoleErrors.push(`pageerror: ${err.message}`));

  // /vulnerabilities does heavy server-side fan-out (~50s cold on a 200-host
  // fleet); networkidle's 15s default never settles. Use domcontentloaded
  // + explicit longer waits on the meaningful UI signals.
  await page.goto("/vulnerabilities", { waitUntil: "domcontentloaded", timeout: 90_000 });

  // Switch to By patch view.
  const byPatch = page.getByRole("button", { name: /By patch/ });
  await expect(byPatch).toBeVisible({ timeout: 90_000 });
  await byPatch.click();

  // Wait for at least one patch row to render.
  await page.waitForSelector("text=/Update /", { timeout: 60_000 });

  // Click first chevron / row that has a fix.
  const firstRow = page.locator("tr.cursor-pointer").first();
  await firstRow.click();

  // Capture screenshot of expanded row.
  await page.screenshot({ path: "tests/screenshots/patch-plan-expanded.png", fullPage: true });

  // Look for the button.
  const planBtn = page.getByRole("button", { name: /Build patch plan/ });
  const visible = await planBtn.isVisible().catch(() => false);
  console.log("[probe] Build patch plan button visible:", visible);
  console.log("[probe] console errors:", consoleErrors);

  // Dump the expanded row's text so we can see what's there.
  const expandedText = await page.locator("tr.bg-black\\/60").first().innerText().catch(() => "(no expanded row found)");
  console.log("[probe] expanded row text (first 600 chars):", expandedText.slice(0, 600));

  // Also dump the first 5 patch row labels for context.
  const labels = await page.locator("tr.cursor-pointer td:nth-child(2)").allInnerTexts();
  console.log("[probe] first 5 patch labels:", labels.slice(0, 5));
});
