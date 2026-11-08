import { test, expect } from "@playwright/test";

// /blueprint is the second developer Reference surface: an advisor that streams
// a "build-your-own agentic SOC" decision document from Claude, grounded in this
// repo's own architecture, with an "Authoritative sources" panel linking out to
// developer.crowdstrike.com. It has NO Falcon dependency (pure LLM synthesis) —
// so this spec does not assume a configured tenant. It asserts user-VISIBLE
// output: the hero, the seed chips, the sources panel, the sidebar entry, and a
// real streamed response.

function filterDevModeNoise(err: string): boolean {
  return !/caret-color/i.test(err);
}

test("blueprint renders and streams a build-analysis decision document", async ({ page }) => {
  const consoleErrors: string[] = [];
  page.on("console", (msg) => {
    if (msg.type() === "error") consoleErrors.push(msg.text());
  });
  page.on("pageerror", (err) => consoleErrors.push(`pageerror: ${err.message}`));

  await page.goto("/blueprint", { waitUntil: "domcontentloaded", timeout: 60_000 });

  // (1) Hero — labeled as a developer reference surface.
  await expect(page.getByText("developer surface")).toBeVisible({ timeout: 30_000 });
  await expect(
    page.getByRole("heading", { name: "Build your own agentic SOC." }),
  ).toBeVisible();

  // (2) Seed blueprints render (empty state), and the authoritative-sources
  // panel renders the outbound dev-portal links.
  await expect(page.getByRole("button", { name: "Approval-gating writes" })).toBeVisible();
  await expect(
    page.getByRole("button", { name: "falcon-mcp vs. FalconPy — when do I need a sidecar?" }),
  ).toBeVisible();

  const falconMcpLink = page.getByRole("link", { name: /Falcon MCP/ });
  await expect(falconMcpLink).toBeVisible();
  await expect(falconMcpLink).toHaveAttribute(
    "href",
    "https://developer.crowdstrike.com/falcon-mcp/overview/",
  );
  // All nine sources link out to developer.crowdstrike.com or the CrowdStrike repos.
  const sourceLinks = page.locator(
    'a[href^="https://developer.crowdstrike.com"], a[href^="https://github.com/CrowdStrike"]',
  );
  expect(await sourceLinks.count()).toBeGreaterThanOrEqual(9);

  // (3) Sidebar Reference group exposes Blueprint alongside Agent toolbox.
  await page.getByRole("button", { name: "Open menu" }).click();
  const sidebar = page.getByRole("complementary", { name: "Primary navigation" });
  await expect(sidebar.getByText("Reference", { exact: true })).toBeVisible();
  await expect(sidebar.getByRole("link", { name: "Blueprint" })).toBeVisible();
  // Close the menu so it doesn't intercept the seed click.
  await page.keyboard.press("Escape");

  // (4) Clicking a seed starts a real Claude stream: the activity banner appears
  // and streamed markdown paints into the output panel.
  await page.getByRole("button", { name: "Approval-gating writes" }).click();
  await expect(page.getByText("blueprint //")).toBeVisible({ timeout: 15_000 });

  const output = page.locator(".markdown").first();
  await expect(output).toBeVisible({ timeout: 45_000 });
  await expect
    .poll(async () => (await output.innerText()).trim().length, { timeout: 45_000 })
    .toBeGreaterThan(80);

  expect(consoleErrors.filter(filterDevModeNoise)).toEqual([]);
});
