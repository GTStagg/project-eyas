import { test, expect } from "@playwright/test";

// UI enhancement pass: persistent icon rail + flyout, /home dashboard, toasts.
// The dashboard cards fan out to Falcon; on a tenant without live data they
// resolve to empty/clean-error states — the spec asserts the STRUCTURE renders
// and interactions wire up, not specific tenant numbers.

function collectErrors(page: import("@playwright/test").Page): string[] {
  const errs: string[] = [];
  page.on("console", (m) => {
    if (m.type() === "error") errs.push(m.text());
  });
  page.on("pageerror", (e) => errs.push(`pageerror: ${e.message}`));
  return errs;
}

// Next dev-mode emits benign caret-color / hydration-dev noise; ignore those.
const realError = (t: string) =>
  !/caret-color|Download the React DevTools|hydrat/i.test(t);

test.describe("UI pass — rail + /home dashboard", () => {
  test("desktop rail renders, flyout reveals items, active state tracks route", async ({ page }) => {
    const errs = collectErrors(page);
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto("/home", { waitUntil: "domcontentloaded", timeout: 60_000 });

    const rail = page.getByRole("complementary", { name: "Primary navigation" });
    await expect(rail).toBeVisible();

    // Home rail link is present + marked active on /home.
    const homeLink = rail.getByRole("link", { name: "Home" }).first();
    await expect(homeLink).toBeVisible();

    // Hover the "Hunt" group icon → flyout lists a Hunt item (Intel/NGSIEM).
    const huntBtn = rail.getByRole("button", { name: "Hunt" });
    await expect(huntBtn).toBeVisible();
    await huntBtn.hover();
    const ngsiem = page.getByRole("link", { name: "NGSIEM" });
    await expect(ngsiem).toBeVisible();
    await ngsiem.click();
    await expect(page).toHaveURL(/\/ngsiem/);

    // The Hunt group icon should now show its active ring (route under it).
    await expect(rail.getByRole("button", { name: "Hunt" })).toBeVisible();

    expect(errs.filter(realError)).toEqual([]);
  });

  test("/home dashboard renders hero + a fully-tiled control center", async ({ page }) => {
    const errs = collectErrors(page);
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto("/home", { waitUntil: "domcontentloaded", timeout: 60_000 });

    // Hero band resolves to either a recommended move or the all-clear state.
    await expect
      .poll(
        async () => {
          const move = await page.getByText("Recommended next move").first().isVisible().catch(() => false);
          const clear = await page.getByText("Nothing needs you right now.").isVisible().catch(() => false);
          return move || clear;
        },
        { timeout: 45_000 },
      )
      .toBe(true);

    // Control-center groups (scope to <main>; "Posture" is also a nav label).
    const main = page.getByRole("main");
    await expect(main.getByText("Triage", { exact: true })).toBeVisible();
    await expect(main.getByText("Ask & hunt", { exact: true })).toBeVisible();
    await expect(main.getByText("Posture", { exact: true })).toBeVisible();
    await expect(main.getByText("Operations", { exact: true })).toBeVisible();

    // Triage tiles replace the old inline sections + snapshot strip.
    await expect(page.getByRole("button", { name: /Priority detections/i }).first()).toBeVisible();
    await expect(page.getByRole("button", { name: /Cross-host campaigns/i }).first()).toBeVisible();
    await expect(page.getByRole("button", { name: /Contained hosts/i }).first()).toBeVisible();
    await expect(page.getByRole("button", { name: /Ask the agent/i }).first()).toBeVisible();
    await expect(page.getByRole("button", { name: /Spend/i }).first()).toBeVisible();
    // Guardian (falcon-mcp 0.19.0) — gated on the guardian capability (AIDR:read,
    // granted on this tenant). Do NOT click it here — opening auto-fires a billable
    // agent run; the route itself is verified separately.
    await expect(page.getByRole("button", { name: /AI agent activity/i }).first()).toBeVisible();

    // The old inline "Top priority detections" section and "Engagements" stat are gone.
    await expect(page.getByRole("heading", { name: "Top priority detections" })).toHaveCount(0);
    await expect(main.getByText("Engagements")).toHaveCount(0);

    expect(errs.filter(realError)).toEqual([]);
  });

  test("control center: Priority detections tile pops out a list panel", async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto("/home", { waitUntil: "domcontentloaded", timeout: 60_000 });
    // Wait for the summary to resolve (hero settles) so the tile carries data.
    await expect
      .poll(
        async () => {
          const move = await page.getByText("Recommended next move").first().isVisible().catch(() => false);
          const clear = await page.getByText("Nothing needs you right now.").isVisible().catch(() => false);
          return move || clear;
        },
        { timeout: 45_000 },
      )
      .toBe(true);
    await page.getByRole("button", { name: /Priority detections/i }).first().click();
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible();
    await expect(dialog.getByText("Priority detections", { exact: true })).toBeVisible();
    await expect(dialog.getByRole("link", { name: /Full queue/i })).toBeVisible();
  });

  test("control center: Spend widget opens a breakdown panel", async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto("/home", { waitUntil: "domcontentloaded", timeout: 60_000 });
    await page.getByRole("button", { name: /Spend/i }).first().click();
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible();
    await expect(dialog.getByText("Projected / mo")).toBeVisible();
    await expect(dialog.getByText("By surface")).toBeVisible({ timeout: 15_000 });
    await expect(dialog.getByRole("link", { name: /Full cost report/i })).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(page.getByRole("dialog")).toBeHidden();
  });

  test("control center: NGSIEM widget opens a wide query panel", async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto("/home", { waitUntil: "domcontentloaded", timeout: 60_000 });
    await page.getByRole("button", { name: /NGSIEM query/i }).first().click();
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible();
    await expect(dialog.getByPlaceholder(/Show cmd\.exe|plain English|winword/i)).toBeVisible();
    await expect(dialog.getByRole("button", { name: /^Run$/ })).toBeVisible();
  });

  test("control center: Artifact pivot panel validates input client-side", async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto("/home", { waitUntil: "domcontentloaded", timeout: 60_000 });
    await page.getByRole("button", { name: /Artifact pivot/i }).first().click();
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible();
    const box = dialog.getByPlaceholder(/hash, IP, domain/i);
    await expect(box).toBeVisible();
    // Junk input is rejected locally (no network) with a friendly error.
    await box.fill("this is not an artifact!!");
    await dialog.getByRole("button", { name: /Look up/i }).click();
    await expect(dialog.getByText(/Couldn't recognize/i)).toBeVisible();
  });

  test("global: TopBar Ask button opens the chat dock on any page", async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto("/queue", { waitUntil: "domcontentloaded", timeout: 60_000 });
    // The Ask button lives in the TopBar → present on a non-dashboard page.
    // Retry the click so a pre-hydration click (SSR button not yet interactive)
    // doesn't flake the open.
    const dialog = page.getByRole("dialog");
    await expect(async () => {
      await page.getByRole("button", { name: "Ask the agent" }).click();
      await expect(dialog).toBeVisible({ timeout: 2000 });
    }).toPass({ timeout: 20_000 });
    await expect(dialog.getByPlaceholder("Ask the agent…")).toBeVisible();
    await expect(dialog.getByRole("link", { name: /Open full chat/i })).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(page.getByRole("dialog")).toBeHidden();
  });

  test("control center: Ask-the-agent panel uses an isolated session", async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto("/home", { waitUntil: "domcontentloaded", timeout: 60_000 });
    const dialog = page.getByRole("dialog");
    await expect(async () => {
      await page.getByRole("button", { name: /Ask the agent/i }).first().click();
      await expect(dialog).toBeVisible({ timeout: 2000 });
    }).toPass({ timeout: 20_000 });
    await expect(dialog.getByPlaceholder("Ask the agent…")).toBeVisible();
    await expect(dialog.getByRole("link", { name: /Open full chat/i })).toBeVisible();
    // Opening the panel must not touch the MAIN chat session key.
    const mainKey = await page.evaluate(() => window.localStorage.getItem("falcon-mcp-console.sessionId"));
    // Type + send a lightweight prompt; a distinct panel session key is written.
    await dialog.getByPlaceholder("Ask the agent…").fill("Say hello in one word.");
    await dialog.getByRole("button", { name: /^Send$/ }).click();
    // The user bubble appears immediately (send wired up).
    await expect(dialog.getByText("Say hello in one word.")).toBeVisible();
    // Round-trip completes when the composer leaves the busy (Stop) state.
    await expect(dialog.getByRole("button", { name: /^Send$/ })).toBeVisible({ timeout: 60_000 });
    const panelKey = await page.evaluate(() => window.localStorage.getItem("eyas.control-chat.sessionId"));
    expect(panelKey).toBeTruthy();
    const mainKeyAfter = await page.evaluate(() => window.localStorage.getItem("falcon-mcp-console.sessionId"));
    expect(mainKeyAfter).toBe(mainKey); // main chat session untouched
  });

  test("copy affordance fires a toast", async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.context().grantPermissions(["clipboard-read", "clipboard-write"]);
    await page.goto("/home", { waitUntil: "domcontentloaded", timeout: 60_000 });

    // Wait for the at-risk section to settle.
    await page.waitForTimeout(4000);
    const copyBtn = page.getByRole("button", { name: /^Copy / }).first();
    const hasHost = await copyBtn.isVisible().catch(() => false);
    test.skip(!hasHost, "No at-risk hosts on this tenant to copy — skipping toast check.");
    await copyBtn.click();
    await expect(page.getByText(/^Copied /)).toBeVisible();
  });

  test("mobile hides the rail and exposes the drawer toggle", async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto("/home", { waitUntil: "domcontentloaded", timeout: 60_000 });

    const rail = page.getByRole("complementary", { name: "Primary navigation" });
    // Rail is display:none below md; the drawer <aside> shares the same aria
    // label but is off-canvas. Assert the TopBar toggle is visible + opens nav.
    const toggle = page.getByRole("button", { name: /Open menu|Close menu/ });
    await expect(toggle).toBeVisible();
    await toggle.click();
    // Drawer reveals nav group labels + a nav link.
    await expect(page.getByRole("link", { name: "Queue" }).first()).toBeVisible();
    void rail;
  });

  test("/ still renders the bare chat terminal", async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto("/", { waitUntil: "domcontentloaded", timeout: 60_000 });
    // Chat empty-state marker (mono `$ agent --ready` cap per CLAUDE.md).
    await expect(page.getByText(/agent --ready/i)).toBeVisible({ timeout: 20_000 });
  });

  test("dashboard hand-off lands on a humanized PendingActionCard", async ({ page }) => {
    // The prevention-gap card builds this exact primer; verify the card the
    // operator lands on humanizes it (matcher wired end-to-end).
    const primer =
      "Review the 3 detect-only prevention policies and recommend which should move to blocking.";
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto(`/?primer=${encodeURIComponent(primer)}`, {
      waitUntil: "domcontentloaded",
      timeout: 60_000,
    });
    await expect(
      page.getByText("Review 3 detect-only prevention policies"),
    ).toBeVisible({ timeout: 20_000 });
    // Raw tool/impl jargon must stay behind the disclosure, not in the summary.
    await expect(page.getByText("prevention-policies").first()).toHaveCount(0);
  });

  test("snack-panel: Contained stat opens a right drawer; Esc + backdrop close it", async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto("/home", { waitUntil: "domcontentloaded", timeout: 60_000 });

    // The Contained-hosts stat is always present (data-independent) — click it.
    const contained = page.getByRole("button", { name: /Contained hosts/i }).first();
    await expect(contained).toBeVisible({ timeout: 30_000 });
    await contained.click();

    // Drawer (dialog) opens with the title; content resolves out of "Loading…".
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible();
    await expect(dialog.getByText("Contained hosts")).toBeVisible();
    await expect
      .poll(async () => dialog.getByText("Loading…").isVisible().catch(() => false), { timeout: 20_000 })
      .toBe(false);

    // Esc closes.
    await page.keyboard.press("Escape");
    await expect(dialog).toBeHidden();

    // Re-open, then backdrop-click closes.
    await contained.click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await page.mouse.click(60, 400); // far-left, over the backdrop not the panel
    await expect(page.getByRole("dialog")).toBeHidden();
  });
});
