import { test, expect } from "@playwright/test";

// Regression for the operator-editable chat output-token cap (anthropic.chatMaxTokens):
// the Anthropic config card must surface it in view mode and expose a numeric
// input in edit mode. See app/api/config/anthropic + components/AnthropicConfigCard.
test("Anthropic card shows + edits the Chat output limit field", async ({ page }) => {
  await page.goto("/config");

  // Scope to the Anthropic card (the only card with the "LLM credentials" heading).
  const card = page
    .locator("div.rounded-lg")
    .filter({ has: page.getByRole("heading", { name: "LLM credentials" }) })
    .first();
  await expect(card).toBeVisible();

  // View mode: a "Chat output limit" row rendered from the GET value.
  await expect(card.getByText("Chat output limit")).toBeVisible();
  await expect(card.getByText(/[\d,]+\s+tokens \/ reply/)).toBeVisible();

  // Edit mode: the numeric input (range 1024–64000) appears.
  await card.getByRole("button", { name: "Edit" }).click();
  const input = card.locator('input[type="number"][max="64000"]');
  await expect(input).toBeVisible();
  await expect(input).toHaveAttribute("min", "1024");
  // Placeholder reflects the current effective value (default 16384).
  await expect(input).toHaveAttribute("placeholder", "16384");
});
