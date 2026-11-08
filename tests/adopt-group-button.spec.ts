import { test, expect, type Locator } from "@playwright/test";

// Verifies the "Adopt existing group by name" control on the /config setup
// cards (IR quarantine + Shadow-AI Banned). Each card should render a labeled
// adopt box with a name input prefilled to the canonical group name and a
// "Find & adopt" button, positioned above the "Or paste the … group id" form.
// Clicking with a bogus name must surface an inline not-found error without
// navigating away or throwing.

// Next.js 15 dev-mode injects a benign caret-color hydration warning on
// focused inputs; everything else is a real bug.
function filterDevModeNoise(err: string): boolean {
  return !/caret-color/i.test(err);
}

function cardByHeading(page: import("@playwright/test").Page, heading: string): Locator {
  return page.locator("section").filter({ has: page.getByRole("heading", { name: heading }) });
}

test("config setup cards render Adopt-by-name above the paste-id form", async ({ page }) => {
  const consoleErrors: string[] = [];
  page.on("console", (msg) => {
    if (msg.type() === "error") consoleErrors.push(msg.text());
  });
  page.on("pageerror", (err) => consoleErrors.push(`pageerror: ${err.message}`));

  await page.goto("/config", { waitUntil: "domcontentloaded" });

  // --- IR quarantine card ---
  const irCard = cardByHeading(page, "IR quarantine setup");
  await expect(irCard).toBeVisible();

  const irAdoptLabel = irCard.getByText("Adopt existing group by name");
  await expect(irAdoptLabel).toBeVisible({ timeout: 15_000 });

  // The adopt input is the first text input in the card; it's prefilled with
  // the canonical name.
  const irAdoptInput = irCard.locator('input[type="text"]').first();
  await expect(irAdoptInput).toHaveValue("Project Eyas - IR Quarantine");
  await expect(irCard.getByRole("button", { name: "Find & adopt" })).toBeVisible();

  // Adopt-by-name sits ABOVE the paste-id form.
  const irPasteLabel = irCard.getByText("Or paste the IR quarantine group id");
  await expect(irPasteLabel).toBeVisible();
  const irAdoptBox = await irAdoptLabel.boundingBox();
  const irPasteBox = await irPasteLabel.boundingBox();
  expect(irAdoptBox).not.toBeNull();
  expect(irPasteBox).not.toBeNull();
  expect(irAdoptBox!.y).toBeLessThan(irPasteBox!.y);

  // --- Shadow-AI Banned card ---
  const shadowCard = cardByHeading(page, "Shadow-AI Banned setup");
  await expect(shadowCard).toBeVisible();

  const shadowAdoptLabel = shadowCard.getByText("Adopt existing group by name");
  await expect(shadowAdoptLabel).toBeVisible({ timeout: 15_000 });

  const shadowAdoptInput = shadowCard.locator('input[type="text"]').first();
  await expect(shadowAdoptInput).toHaveValue("Project Eyas - Shadow-AI Banned");
  await expect(shadowCard.getByRole("button", { name: "Find & adopt" })).toBeVisible();

  const shadowPasteLabel = shadowCard.getByText("Or paste the Shadow-AI Banned group id");
  await expect(shadowPasteLabel).toBeVisible();
  const shadowAdoptBox = await shadowAdoptLabel.boundingBox();
  const shadowPasteBox = await shadowPasteLabel.boundingBox();
  expect(shadowAdoptBox).not.toBeNull();
  expect(shadowPasteBox).not.toBeNull();
  expect(shadowAdoptBox!.y).toBeLessThan(shadowPasteBox!.y);

  // --- Inline error path (bogus name) on the IR card ---
  // Typing a name that doesn't exist in the tenant returns {ok:false} at HTTP
  // 200 — the control must render the inline not-found copy, NOT crash or
  // navigate. (Using a bogus name avoids mutating tenant config; the prefilled
  // canonical name would resolve+save on a provisioned tenant.)
  await irAdoptInput.fill("No Such Group ZZZ 9999");
  await irCard.getByRole("button", { name: "Find & adopt" }).click();

  await expect(irCard.getByText(/No host group named/i)).toBeVisible({ timeout: 15_000 });

  // Did not navigate away from /config.
  expect(page.url()).toContain("/config");

  const realErrors = consoleErrors.filter(filterDevModeNoise);
  console.log("[probe] filtered console errors:", realErrors);
  // The bogus-name response is HTTP 200 {ok:false} — handled inline, so it
  // produces no console/network error and no unhandled rejection.
  expect(realErrors).toEqual([]);
});
