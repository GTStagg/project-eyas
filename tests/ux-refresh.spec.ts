import { test, expect, type Page } from "@playwright/test";

// Verifies the structural UX changes shipped in the May 2026 refresh that
// remain stable. Copy-level assertions for /detections, root chat,
// /pivot, /prevention, /briefing were retired 2026-05-08 — the pages
// were re-copy-edited post-refresh and the tests had drifted. The smoke
// spec covers "renders without console errors" for all of those routes.
//  - Lazy auto-start on /identity, /workflows (host-groups deleted; redirect)
//  - Sidebar regrouped (Triage / Pivot / Hunt / Posture)
//  - /hosts has Group posture report panel
//  - /lookup → /pivot, /threat-graph → /pivot?mode=lineage redirects

function trackErrors(page: Page) {
  const errors: string[] = [];
  page.on("console", (msg) => {
    if (msg.type() === "error") {
      const t = msg.text();
      // Filter dev-mode noise (caret-color hydration warnings).
      if (/caret-color/i.test(t)) return;
      errors.push(t);
    }
  });
  page.on("pageerror", (err) => errors.push(`pageerror: ${err.message}`));
  return errors;
}

test.describe("UX refresh", () => {
  test("/identity does not auto-start; Generate report button visible", async ({ page }) => {
    const errors = trackErrors(page);
    await page.goto("/identity", { waitUntil: "networkidle" });
    await expect(page.getByRole("heading", { name: /Risky identities/i })).toBeVisible();
    await expect(page.getByRole("button", { name: /Generate report/i })).toBeVisible();
    // Empty hint instructs user to click.
    await expect(page.getByText(/Click .* to start/i)).toBeVisible();
    expect(errors).toEqual([]);
  });

  test("/workflows does not auto-start", async ({ page }) => {
    const errors = trackErrors(page);
    await page.goto("/workflows", { waitUntil: "networkidle" });
    await expect(page.getByRole("button", { name: /Generate report/i })).toBeVisible();
    await expect(page.getByText(/Click .* to start/i)).toBeVisible();
    expect(errors).toEqual([]);
  });

  test("/host-groups redirects to /hosts", async ({ page }) => {
    await page.goto("/host-groups", { waitUntil: "networkidle" });
    expect(page.url()).toMatch(/\/hosts$/);
  });

  test("Sidebar groups: Triage / Pivot / Hunt / Posture", async ({ page }) => {
    // The drawer is the mobile nav; on desktop the persistent IconRail replaces
    // it (group labels live in per-group hover flyouts). Use a mobile viewport
    // so the drawer toggle is present, then assert the grouped labels.
    await page.setViewportSize({ width: 375, height: 700 });
    await page.goto("/", { waitUntil: "networkidle" });
    const menuButton = page.getByRole("button", { name: /menu|navigation/i }).first();
    await menuButton.click();
    // Scope to the drawer landmark — the desktop rail also carries these labels
    // in hidden hover-flyouts, which would shadow a page-wide getByText.
    const drawer = page.getByRole("complementary", { name: "Navigation menu" });
    for (const label of ["Triage", "Pivot", "Hunt", "Posture", "Dashboards", "System"]) {
      await expect(drawer.getByText(label, { exact: true }).first()).toBeVisible({ timeout: 5_000 });
    }
  });

  test("/hosts shows Group posture report panel", async ({ page }) => {
    const errors = trackErrors(page);
    await page.goto("/hosts", { waitUntil: "networkidle" });
    await expect(page.getByText(/Group posture report/i)).toBeVisible();
    expect(errors).toEqual([]);
  });

  test("/lookup redirects to /pivot (preserves q)", async ({ page }) => {
    await page.goto("/lookup?q=abc123", { waitUntil: "networkidle" });
    expect(page.url()).toMatch(/\/pivot\?q=abc123$/);
  });

  test("/threat-graph redirects to /pivot?mode=lineage", async ({ page }) => {
    await page.goto("/threat-graph", { waitUntil: "networkidle" });
    expect(page.url()).toMatch(/\/pivot\?mode=lineage$/);
  });

});
