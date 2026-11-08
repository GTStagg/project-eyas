import { test, expect } from "@playwright/test";

// Validates the annotation-backed approval-gate backstop END TO END against the
// live falcon-mcp bridge:
//   1. MCP tool annotations (readOnlyHint:false) actually flow from
//      falcon-mcp 0.13.0 through buildToolBridge into the catalog — if they
//      didn't, `annotatedNativeWrites` would be empty and the backstop inert.
//   2. The healthy invariant holds: every annotated-write native tool is gated,
//      so `driftWarnings` is empty and the /agent-toolbox banner is absent.
//   3. When a native write is dropped from REQUIRES_APPROVAL (simulating a
//      falcon-mcp bump that added a write we forgot to gate), it surfaces in
//      `driftWarnings` and the amber banner renders. This test runs only after
//      the harness comments `falcon_add_ioc` out of the registry.
//
// page.request shares the browser context's sealed session cookie, so the
// authenticated catalog API is reachable directly.

const CATALOG_API = "/api/agent-toolbox-catalog?force=1";

test("annotations flow from live falcon-mcp and there is no drift", async ({ page }) => {
  const resp = await page.request.get(CATALOG_API);
  expect(resp.status()).toBe(200);
  const catalog = await resp.json();
  expect(catalog.ok).toBe(true);

  const byName = new Map<string, { gated: boolean; annotatedWrite: boolean }>(
    catalog.tools.map((t: { name: string; gated: boolean; annotatedWrite: boolean }) => [
      t.name,
      { gated: t.gated, annotatedWrite: t.annotatedWrite },
    ]),
  );

  // Annotations reach us: several known VISIBLE native writes are flagged
  // annotatedWrite (falcon-mcp 0.13.0 sets readOnlyHint:false on these), and
  // each is also gated. Suppressed natives (falcon_update_detections etc.) are
  // absent from the catalog by design, so we assert only on exposed ones.
  for (const name of [
    "falcon_add_ioc",
    "falcon_create_case",
    "falcon_delete_ioa_rules",
    "falcon_perform_policy_action", // adopted native write
  ]) {
    expect(byName.get(name), `${name} present in catalog`).toBeTruthy();
    expect(byName.get(name)?.annotatedWrite, `${name} annotatedWrite`).toBe(true);
    expect(byName.get(name)?.gated, `${name} gated`).toBe(true);
  }

  // Not accidentally empty — annotations really populated across the surface.
  const annotatedCount = catalog.tools.filter(
    (t: { annotatedWrite: boolean }) => t.annotatedWrite,
  ).length;
  expect(annotatedCount).toBeGreaterThanOrEqual(10);

  // Healthy invariant: annotatedWrite ⇒ gated, so no drift.
  const drift = catalog.tools
    .filter((t: { annotatedWrite: boolean; gated: boolean }) => t.annotatedWrite && !t.gated)
    .map((t: { name: string }) => t.name);
  expect(drift).toEqual([]);
  expect(catalog.driftWarnings).toEqual([]);

  // The page renders without the banner.
  await page.goto("/agent-toolbox", { waitUntil: "domcontentloaded", timeout: 60_000 });
  await expect(
    page.getByRole("heading", { name: "One AI, the entire live Falcon tool surface." }),
  ).toBeVisible({ timeout: 30_000 });
  await expect(page.getByText("Approval-gate drift", { exact: false })).toHaveCount(0);
});

// The drift state can't be produced without dropping a real native write from
// REQUIRES_APPROVAL, so this is gated behind DRIFT_TEST and skipped in normal
// runs (the healthy invariant is no drift). To verify the banner: comment
// `"falcon_add_ioc",` out of lib/mcp/write-tools.ts, then
//   DRIFT_TEST=1 npx playwright test tests/drift-banner.spec.ts -g "drift banner"
// and revert the edit afterwards. Verified 2026-07-01 → tests/screenshots/drift-banner.png.
test("drift banner renders when a native write is ungated", async ({ page }) => {
  test.skip(!process.env.DRIFT_TEST, "manual only — see comment; set DRIFT_TEST=1 after ungating falcon_add_ioc");
  // Precondition: the harness has commented `falcon_add_ioc` out of
  // REQUIRES_APPROVAL. Force a fresh catalog so the page (shared cache) sees it.
  const resp = await page.request.get(CATALOG_API);
  expect(resp.status()).toBe(200);
  const catalog = await resp.json();
  expect(catalog.driftWarnings).toContain("falcon_add_ioc");

  await page.goto("/agent-toolbox", { waitUntil: "domcontentloaded", timeout: 60_000 });
  const banner = page.locator("div", { hasText: "Approval-gate drift" }).first();
  await expect(banner).toBeVisible({ timeout: 30_000 });
  await expect(
    page.getByText("falcon_add_ioc", { exact: true }).first(),
  ).toBeVisible();
  await page.screenshot({ path: "tests/screenshots/drift-banner.png", fullPage: false });
});
