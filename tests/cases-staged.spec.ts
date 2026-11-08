import { test, expect, type Page } from "@playwright/test";

// Cases surface (falcon-mcp 0.10.0 cases module). Cases:read is not in this
// tenant's granted scopes, so the expected primary state is the staged-build
// scope-pending banner + the /cases nav item hidden by the capability gate.
// The spec asserts the correct behaviour for WHICHEVER state the live tenant
// is in (granted → table; denied → banner + nav hidden).
//
// Robustness: /api/cases and /api/health both spawn uvx falcon-mcp, and
// falcon-mcp serializes JSON-RPC per client — under full-suite load these
// round-trips can take tens of seconds. Use web-first waits with generous
// timeouts, never fixed sleeps, and don't block navigation on a slow probe.

const UPSTREAM_TIMEOUT = 90_000;

test.use({ viewport: { width: 1280, height: 800 } });
test.describe.configure({ timeout: 150_000 });

function captureConsoleErrors(page: Page): { errors: string[] } {
  const errors: string[] = [];
  page.on("console", (msg) => {
    if (msg.type() === "error") errors.push(msg.text());
  });
  page.on("pageerror", (err) => errors.push(`pageerror: ${err.message}`));
  return { errors };
}
function filterDevModeNoise(err: string): boolean {
  if (/HMR|webpack-hmr|websocket/i.test(err)) return false;
  if (/hydrat/i.test(err) && /caret-color/i.test(err)) return false;
  return true;
}
async function casesCapability(page: Page): Promise<boolean | undefined> {
  const health = await page.request.get("/api/health", { timeout: UPSTREAM_TIMEOUT });
  expect(health.status()).toBeLessThan(400);
  return (await health.json())?.falconMcp?.capabilities?.cases;
}

test("cases: page renders cleanly and matches scope state", async ({ page }) => {
  const consoleState = captureConsoleErrors(page);

  const resp = await page.goto("/cases", { waitUntil: "domcontentloaded" });
  expect(resp?.status(), "HTTP status for /cases").toBeLessThan(400);
  expect(page.url(), "/cases should not redirect to /login").not.toMatch(/\/login/);

  // AppShell TopBar — same assertion the smoke uses.
  await expect(
    page.getByRole("button", { name: /open menu|close menu/i }),
    "/cases should render the AppShell TopBar",
  ).toBeVisible({ timeout: 10_000 });

  // The page resolves its /api/cases fetch into exactly one definite state:
  // the scope-pending banner OR the cases table header. Wait for whichever
  // (web-first, generous) instead of sleeping a fixed interval.
  const banner = page.getByText("Scope pending", { exact: false });
  const tableHeader = page.getByRole("columnheader", { name: /Severity/i });
  await expect(
    banner.or(tableHeader),
    "/cases must resolve to either the scope-pending banner or the table",
  ).toBeVisible({ timeout: UPSTREAM_TIMEOUT });

  // Now cross-check the resolved state against the capability probe — they
  // must agree (route + probe key on identical scope-denial phrases).
  const casesCap = await casesCapability(page);
  expect(casesCap, "falconMcp.capabilities.cases must be probed").not.toBeUndefined();

  if (casesCap === false) {
    await expect(banner).toBeVisible();
    await expect(
      page.getByText("Cases (Read)", { exact: true }),
      "scope-pending banner names the missing scope",
    ).toBeVisible();
  } else {
    await expect(tableHeader).toBeVisible();
  }

  await page.screenshot({ path: "tests/screenshots/desktop/cases.png", fullPage: true });

  const realErrors = consoleState.errors.filter(filterDevModeNoise);
  expect(realErrors, "Console errors on /cases").toEqual([]);
});

test("cases: required scopes are surfaced on /status", async ({ page }) => {
  // /status renders <ScopeChecklist initiallyOpen /> so the tiers are
  // expanded without a click. The operator must be able to see exactly
  // which Falcon scopes to enable for the new functionality.
  // /status is a heavy page (health fanout); first hit on `next dev`
  // cold-compiles well past the default nav timeout.
  await page.goto("/status", { waitUntil: "domcontentloaded", timeout: UPSTREAM_TIMEOUT });

  await expect(
    page.getByText(/Case management .* light up \/cases/i),
    "the Case-management scope tier must be shown",
  ).toBeVisible({ timeout: 15_000 });

  // The two console scope rows the operator ticks in the Falcon console.
  // Scope to <main> — "Cases" also appears as a sidebar nav link until the
  // capability probe resolves and hides it.
  const main = page.getByRole("main");
  await expect(main.getByText("Cases", { exact: true })).toBeVisible();
  await expect(main.getByText("Case Templates", { exact: true })).toBeVisible();

  // Cloud + SaaS Security scopes are surfaced as concrete rows + the
  // optional/agent-only caveat.
  await expect(
    main.getByText("Cloud Security API Detections", { exact: true }),
    "Cloud Security detections scope row must be shown",
  ).toBeVisible();
  await expect(
    main.getByText("Falcon Shield (SaaS Security)", { exact: true }),
    "Falcon Shield scope row must be shown",
  ).toBeVisible();
  await expect(
    page.getByText(/agent-only in chat; no page; entirely optional/i),
  ).toBeVisible();
});

test("cases: capability gate hides the nav item when scope denied", async ({ page }) => {
  const casesCap = await casesCapability(page);

  await page.goto("/", { waitUntil: "domcontentloaded" });
  await page.getByRole("button", { name: /open menu/i }).click();

  const casesLink = page.getByRole("link", { name: "Cases", exact: true });
  if (casesCap === false) {
    // The Sidebar fetches /api/health then filters. toHaveCount auto-retries,
    // so this waits out the probe instead of sleeping.
    await expect(
      casesLink,
      "Cases nav link must be hidden when capability is false",
    ).toHaveCount(0, { timeout: UPSTREAM_TIMEOUT });
  } else {
    await expect(
      casesLink,
      "Cases nav link must be present when capability is true",
    ).toBeVisible({ timeout: UPSTREAM_TIMEOUT });
  }
});
