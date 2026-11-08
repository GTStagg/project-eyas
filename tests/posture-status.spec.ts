import { test, expect } from "@playwright/test";

// /status renders a "Posture history" card from pure DB reads (no upstream
// Falcon calls). This spec assumes >=1 snapshot already exists in the local
// DB (the daily capture or a manual fire writes one); it asserts the populated
// "Latest capture" readout, not the empty state.
test("status page shows the posture-history card with a latest capture", async ({ page }) => {
  const consoleErrors: string[] = [];
  page.on("console", (msg) => {
    if (msg.type() === "error") consoleErrors.push(msg.text());
  });
  page.on("pageerror", (err) => consoleErrors.push(`pageerror: ${err.message}`));

  await page.goto("/status", { waitUntil: "domcontentloaded", timeout: 60_000 });

  // Eyebrow + headline.
  await expect(page.getByText("Posture history", { exact: true })).toBeVisible({ timeout: 30_000 });
  await expect(page.getByRole("heading", { name: "Trend snapshots" })).toBeVisible();

  // Populated state: the "Latest capture" group with its three readouts.
  // The outer card is the `p-8` div; the Group is a sibling inside it.
  const card = page.locator("div.p-8", {
    has: page.getByRole("heading", { name: "Trend snapshots" }),
  });
  await expect(card.getByText("Latest capture", { exact: true })).toBeVisible();
  await expect(card.getByText("Captured", { exact: true })).toBeVisible();
  await expect(card.getByText("Snapshots stored", { exact: true })).toBeVisible();
  await expect(card.getByText("Coverage", { exact: true })).toBeVisible();

  // "Snapshots stored" value must be a positive integer (the empty state would
  // have rendered the "No snapshots captured yet" copy instead).
  const storedRow = card.getByText("Snapshots stored", { exact: true }).locator("..");
  const storedText = await storedRow.innerText();
  const match = storedText.match(/(\d+)/);
  expect(match).not.toBeNull();
  expect(Number(match![1])).toBeGreaterThan(0);

  expect(consoleErrors).toEqual([]);
});
