import { test, expect, type Page } from "@playwright/test";
import { mkdirSync } from "node:fs";

// Pages to smoke-check. Assertions are intentionally LOOSE — we want the
// smoke to verify "the page renders without redirecting to /login and
// without runtime errors", not specific UI copy that drifts every release.
// Per-feature specs (investigate-bl, patch-plan-button, etc.) carry the
// tight assertions for their surface.
type PageCheck = { path: string };
const PAGES: PageCheck[] = [
  { path: "/" },
  { path: "/briefing" },
  { path: "/investigate" },
  { path: "/ngsiem" },
  { path: "/detections" },
  { path: "/hosts" },
  { path: "/vulnerabilities" },
  { path: "/status" },
];

const VIEWPORTS = [
  { name: "desktop", width: 1280, height: 800 },
  { name: "tablet", width: 768, height: 1024 },
  { name: "mobile", width: 375, height: 700 },
];

const SCREENSHOTS_DIR = "tests/screenshots";
mkdirSync(SCREENSHOTS_DIR, { recursive: true });
for (const v of VIEWPORTS) {
  mkdirSync(`${SCREENSHOTS_DIR}/${v.name}`, { recursive: true });
}

function captureConsoleErrors(page: Page): { errors: string[] } {
  const errors: string[] = [];
  page.on("console", (msg) => {
    if (msg.type() === "error") errors.push(msg.text());
  });
  page.on("pageerror", (err) => errors.push(`pageerror: ${err.message}`));
  return { errors };
}

/** Filter dev-only console noise so tests fail only on real bugs.
 *
 * - Next.js 15 dev-mode injects `style="caret-color: transparent"` on input
 *   elements after first paint. SSR doesn't have it, hydration sees the diff
 *   and warns. Production (`next build`) doesn't do this.
 * - HMR / websocket disconnect noise during test teardown.
 *
 * Anything NOT matching these stays in the array and fails the test —
 * including real hydration mismatches in our own code. */
function filterDevModeNoise(err: string): boolean {
  if (/HMR|webpack-hmr|websocket/i.test(err)) return false;
  if (
    /hydrat/i.test(err) &&
    /caret-color/i.test(err)
  )
    return false;
  return true;
}

function safeName(path: string): string {
  return path === "/" ? "_root" : path.replace(/^\//, "").replace(/\//g, "_");
}

for (const v of VIEWPORTS) {
  test.describe(`${v.name} (${v.width}x${v.height})`, () => {
    test.use({ viewport: { width: v.width, height: v.height } });

    for (const p of PAGES) {
      test(`page ${p.path} loads cleanly`, async ({ page }) => {
        const consoleState = captureConsoleErrors(page);

        const resp = await page.goto(p.path, { waitUntil: "domcontentloaded" });
        expect(resp?.status(), `HTTP status for ${p.path}`).toBeLessThan(400);

        // Asserts the auth gate didn't bounce us. (The auth-setup project
        // seals a session cookie via AUTH_SESSION_SECRET — if the secret
        // doesn't match the server's, every page would redirect here.)
        expect(page.url(), `${p.path} should not redirect to /login`).not.toMatch(/\/login/);

        // The TopBar (sticky header with hamburger) is rendered by every
        // gated page via AppShell. If it's not visible the page is broken
        // in a way the smoke should catch.
        await expect(
          page.getByRole("button", { name: /open menu|close menu/i }),
          `${p.path} should render the AppShell TopBar`,
        ).toBeVisible({ timeout: 8000 });

        // Give async render + any client-side fetches a moment to settle so
        // delayed errors land in our consoleState.errors array before assertion.
        await page.waitForTimeout(800);

        await page.screenshot({
          path: `${SCREENSHOTS_DIR}/${v.name}/${safeName(p.path)}.png`,
          fullPage: true,
        });

        const realErrors = consoleState.errors.filter(filterDevModeNoise);

        expect(realErrors, `Console errors on ${p.path}`).toEqual([]);
      });
    }
  });
}

// Interactive smoke: chat actually sends and receives.
test.describe("desktop interactive", () => {
  test.use({ viewport: { width: 1280, height: 800 } });

  test("chat: send a prompt and receive a response", async ({ page }) => {
    const consoleState = captureConsoleErrors(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });

    // Wait for hydration: the textarea is visible immediately, but sessionId
    // is set inside a useEffect (loads from localStorage). React 19 +
    // Playwright controlled-input races mean a fast .fill() can lose chars,
    // so wait first.
    await page.waitForTimeout(1500);

    // Type a small, stable prompt directly. Avoids depending on whatever
    // example-prompt copy the chat surface ships this week.
    const textarea = page.getByRole("textbox").first();
    await textarea.fill("Say hello in one word.");

    const send = page.getByRole("button", { name: /^Send$/i });
    await expect(send).toBeEnabled({ timeout: 10_000 });
    await send.click();

    // Wait for the assistant to start streaming text (any non-empty markdown
    // bubble means the round-trip works).
    await expect(
      page.locator(".markdown").first(),
    ).toBeVisible({ timeout: 60_000 });

    const realErrors = consoleState.errors.filter(filterDevModeNoise);
    expect(realErrors, "Console errors during chat").toEqual([]);
  });
});
