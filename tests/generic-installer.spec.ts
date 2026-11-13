import { test, expect } from "@playwright/test";

// Generic Windows installer (win-app-install) discoverability on /vulnerabilities.
//
// The "capability gap" badge + generic-installer / save-profile affordances only
// render when a live Spotlight remediation is Windows AND no curated patch script
// matches it (server-stamped capability_gap via extras_classify_patch_coverage).
// Whether the active tenant currently has such a remediation is data-dependent —
// so this spec is written to be DECISIVE either way:
//   * it always regression-guards that the By-patch table still renders rows
//     (my VulnerabilitiesTable branch must not break the curated path);
//   * it extracts every patch-group label so the operator can confirm coverage;
//   * IF a gap badge is present it asserts the affordances + copy hygiene
//     (no dev jargon, no purple) — the whole point of the feature.

test("capability-gap badge + affordances on /vulnerabilities (or none if tenant is fully covered)", async ({
  page,
}) => {
  const consoleErrors: string[] = [];
  page.on("console", (m) => {
    if (m.type() !== "error") return;
    const t = m.text();
    // Next dev-mode caret-color / hydration-noise filter (mirrors filterDevModeNoise).
    if (/caret-color|Download the React DevTools|Fast Refresh/i.test(t)) return;
    consoleErrors.push(t);
  });

  // Heavy server-side fan-out; networkidle never settles. domcontentloaded + an
  // explicit wait for the By-patch control is the right shape (see run-patch-button).
  await page.goto("/vulnerabilities", { waitUntil: "domcontentloaded", timeout: 90_000 });
  await expect(page).not.toHaveURL(/\/login/);

  await page.getByRole("button", { name: /By patch/ }).click({ timeout: 90_000 });
  await page.waitForSelector("tr.cursor-pointer", { timeout: 90_000 });

  const rowCount = await page.locator("tr.cursor-pointer").count();
  console.log("[probe] By-patch rows:", rowCount);
  expect(rowCount).toBeGreaterThan(0); // regression: curated table still renders

  // The generic-installer coverage-gap badge (label text "generic installer").
  const gapBadges = page.getByText("generic installer", { exact: false });
  const gapCount = await gapBadges.count();
  console.log("[probe] capability-gap badges visible:", gapCount);

  if (gapCount === 0) {
    console.log(
      "[probe] No capability gap in the active tenant's live Spotlight data — every Windows remediation maps to a curated script. Badge branch not exercised against live data (verified deterministically by test:rtr-library instead).",
    );
  } else {
    // A gap row exists — assert the feature renders end-to-end.
    const gapRow = page.locator("tr.cursor-pointer", { has: page.getByText("generic installer") }).first();
    await gapRow.click();

    // Both affordances present, in operator language (no tool names / jargon).
    const installBtn = page.getByRole("button", { name: /generic installer|install/i }).first();
    const saveBtn = page.getByRole("button", { name: /save.*profile|save as profile/i }).first();
    await expect(installBtn).toBeVisible({ timeout: 30_000 });
    await expect(saveBtn).toBeVisible({ timeout: 30_000 });

    // Copy hygiene: no dev jargon anywhere in the expanded gap region.
    const regionText = (await gapRow.locator("xpath=..").textContent()) ?? "";
    expect(regionText).not.toMatch(/win-app-install|extras_|falcon_|FalconPy|sidecar|manifest|RTR script library/i);

    // No purple (project rule). Check class soup of the gap row subtree.
    const html = (await gapRow.locator("xpath=..").innerHTML()) ?? "";
    expect(html).not.toMatch(/purple|violet|fuchsia/i);
  }

  expect(consoleErrors, `unexpected console errors: ${consoleErrors.join(" | ")}`).toEqual([]);
});
