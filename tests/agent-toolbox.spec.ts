import { test, expect } from "@playwright/test";

// /agent-toolbox is the developer Reference surface: it renders the EXACT
// agent-visible tool catalog (post-suppression) from the live falcon-mcp +
// extension bridge, each tool tagged read-only vs. approval-gated, with its
// JSON input schema behind a disclosure. This spec asserts user-VISIBLE output
// (real tool rows, working filters, an expanded schema), not derived counts —
// per the verify-feature anti-pattern note. Assumes Falcon is configured so the
// catalog builds (the box this runs on has live falcon-mcp + sidecar).

// Next.js 15 dev-mode injects a caret-color hydration warning on focused
// inputs; it's noise, not a real error.
function filterDevModeNoise(err: string): boolean {
  return !/caret-color/i.test(err);
}

test("agent toolbox renders the live tool catalog with working filters", async ({ page }) => {
  const consoleErrors: string[] = [];
  page.on("console", (msg) => {
    if (msg.type() === "error") consoleErrors.push(msg.text());
  });
  page.on("pageerror", (err) => consoleErrors.push(`pageerror: ${err.message}`));

  await page.goto("/agent-toolbox", { waitUntil: "domcontentloaded", timeout: 60_000 });

  // Hero is explicitly labeled as a developer reference surface.
  await expect(page.getByText("developer surface")).toBeVisible({ timeout: 30_000 });
  await expect(
    page.getByRole("heading", { name: "One AI, the entire live Falcon tool surface." }),
  ).toBeVisible();

  // Catalog is populated: a known read-only falcon-mcp tool row is actually
  // visible (not just a header count).
  const readTool = page.getByText("falcon_search_detections", { exact: true });
  await expect(readTool).toBeVisible();
  // A known approval-gated extension tool is also present by default.
  await expect(page.getByText("extras_host_contain", { exact: true })).toBeVisible();

  // Search narrows the list: "host_contain" keeps the containment tool and drops
  // the detections search tool entirely.
  const search = page.getByPlaceholder("Filter tools…");
  await search.fill("host_contain");
  await expect(page.getByText("extras_host_contain", { exact: true })).toBeVisible();
  await expect(page.getByText("falcon_search_detections", { exact: true })).toHaveCount(0);
  await search.fill("");
  await expect(page.getByText("falcon_search_detections", { exact: true })).toBeVisible();

  // Approval-gated chip shows gated tools and hides read-only ones.
  await page.getByRole("button", { name: "Approval-gated" }).click();
  await expect(page.getByText("extras_host_contain", { exact: true })).toBeVisible();
  await expect(page.getByText("falcon_search_detections", { exact: true })).toHaveCount(0);
  // Back to the full catalog.
  await page.getByRole("button", { name: "All" }).click();
  await expect(page.getByText("falcon_search_detections", { exact: true })).toBeVisible();

  // Expanding a tool row reveals its JSON input schema.
  const containRow = page.locator("details", {
    has: page.getByText("extras_host_contain", { exact: true }),
  });
  await expect(containRow.getByText("Input schema", { exact: true })).not.toBeVisible(); // collapsed
  await containRow.locator("summary").click();
  await expect(containRow.getByText("Input schema", { exact: true })).toBeVisible();

  // The "why suppressed" disclosure lists a native write that is NOT in the
  // catalog (proving the curation story is surfaced honestly).
  const why = page.locator("details", {
    has: page.getByText("Why are some native writes not shown?"),
  });
  await why.locator("summary").click();
  await expect(why.getByText("falcon_update_detections", { exact: true })).toBeVisible();

  // The page is reachable from the sidebar's dedicated Reference group — a
  // developer surface intentionally segregated from the operator nav groups.
  await page.getByRole("button", { name: "Open menu" }).click();
  const sidebar = page.getByRole("complementary", { name: "Primary navigation" });
  await expect(sidebar.getByText("Reference", { exact: true })).toBeVisible();
  await expect(sidebar.getByRole("link", { name: "Agent toolbox" })).toBeVisible();

  expect(consoleErrors.filter(filterDevModeNoise)).toEqual([]);
});
