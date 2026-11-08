import { test, expect } from "@playwright/test";

test("/shadow-ai renders panel + populates from fleet egress scan", async ({
  page,
}) => {
  const consoleErrors: string[] = [];
  page.on("console", (msg) => {
    if (msg.type() === "error") consoleErrors.push(msg.text());
  });
  page.on("pageerror", (err) => consoleErrors.push(`pageerror: ${err.message}`));

  await page.goto("/shadow-ai", { waitUntil: "domcontentloaded" });

  // Hero copy + panel header are in the DOM immediately (server-rendered).
  await expect(
    page.getByRole("heading", {
      name: /Find unsanctioned generative-AI tooling/i,
    }),
  ).toBeVisible();
  await expect(
    page.getByText("Fleet egress scan", { exact: false }),
  ).toBeVisible();

  // Hours selector chips are present.
  await expect(
    page.getByRole("button", { name: "24h", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "168h", exact: true }),
  ).toBeVisible();

  // Wait for the fleet API to settle. The panel renders one of three
  // terminal states: an items list, "No DNS queries..." empty state, or
  // an error banner. Assert one of them appears so we know the network
  // round-trip completed without leaving the page in a permanent
  // loading skeleton.
  const itemHeading = page.getByRole("heading", {
    name: /host(?:s)? with AI egress signal/i,
  });
  const emptyHint = page.getByText(/No DNS queries to known AI-egress/i);
  const scopePending = page.getByText(/NGSIEM scope is not granted/i);
  await expect(
    itemHeading.or(emptyHint).or(scopePending),
  ).toBeVisible({ timeout: 30000 });

  // Switch the hours selector and verify the panel re-fetches without
  // crashing (catches the most common useEffect dep mistake).
  await page.getByRole("button", { name: "168h", exact: true }).click();
  // Brief pause for refetch state to settle.
  await page.waitForTimeout(1500);

  // Filter dev-mode noise — same pattern as smoke spec. Only flag real
  // errors. Next.js dev HMR sometimes logs a benign 'caret-color' warning.
  const real = consoleErrors.filter(
    (e) =>
      !e.includes("caret-color") &&
      !e.includes("Download the React DevTools"),
  );
  console.log("[probe] console errors:", consoleErrors);
  expect(real, "no real console errors").toEqual([]);
});
