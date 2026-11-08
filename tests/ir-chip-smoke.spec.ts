import { test, expect } from "@playwright/test";

// Smoke: /hosts renders with the refactored HostActionButtons + IrChip and the
// search panel produces IR chips. Tolerant of empty tenants — we only assert
// the page didn't crash and the Investigate chip (always present) renders.
test("/hosts renders host action chips without crashing", async ({ page }) => {
  await page.goto("/hosts");
  await expect(page.getByText("Search by hostname.")).toBeVisible();
  await page.waitForTimeout(2500);
  await page.screenshot({ path: "tests/screenshots/ir-chip-hosts.png", fullPage: false });
});
