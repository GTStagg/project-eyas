import { test, expect } from "@playwright/test";

test("Intel Hunt button surfaces a primer on /intel when matches exist", async ({ page }) => {
  // /intel does intel hunt + tenant cross-reference; can take 30+s on cold MCP.
  await page.goto("/intel", { waitUntil: "domcontentloaded", timeout: 90_000 });

  // The Hunt panel only renders match rows when the API returns matches.
  // Probe the API first to decide whether to skip.
  const apiResp = await page.request.get("/api/intel/hunt", { timeout: 90_000 });
  const apiJson = await apiResp.json().catch(() => null);
  const matches = (apiJson?.matches ?? []) as unknown[];
  if (!apiResp.ok() || matches.length === 0) {
    test.skip(true, "Tenant has no intel hunt matches — nothing to assert.");
  }

  // Active hits render by default; covered/watchlist tiers are behind two
  // disclosure buttons. Click both if present so a MatchCard is in the DOM.
  for (const re of [/Show \d+ covered\/watchlist/i, /show watchlist tiers/i]) {
    const btn = page.getByRole("button", { name: re });
    await btn
      .first()
      .click({ timeout: 10_000 })
      .catch(() => {
        /* not present is fine */
      });
  }

  // Hand-off button is labeled "Investigate" (active_in_tenant) or "Enrich"
  // (watchlist_only / covered_by_intel) per IntelHuntPanel MatchCard.
  const handoff = page.getByRole("button", { name: /^(Investigate|Enrich)$/ }).first();
  await expect(handoff).toBeVisible({ timeout: 60_000 });
  await handoff.click();

  // Click navigates to /?primer=...
  await page.waitForURL(/\?primer=/, { timeout: 10_000 });
  const url = new URL(page.url());
  const primer = url.searchParams.get("primer") ?? "";

  // Trimmed primer: must lead with one of the two declarative openers,
  // and must contain a backtick-quoted indicator string.
  expect(primer).toMatch(/^(Investigate the active intel hit|Look up indicator)/);
  expect(primer).toMatch(/`[^`]+`/);

  // Forbidden phrases (decision-doc scaffolding / ask-permission boilerplate
  // — covered by the chat system prompt, not the primer).
  expect(primer).not.toMatch(/tell me whether/i);
  expect(primer).not.toMatch(/proactively add/i);
});
