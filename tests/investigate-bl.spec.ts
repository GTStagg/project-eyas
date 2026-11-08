import { test, expect } from "@playwright/test";
import { mkdirSync, writeFileSync } from "node:fs";

// Live diagnostic against a real tenant host.
const HOST = process.env.EYAS_TEST_HOST ?? "WIN10-FIN-07";
const OUT = "tests/screenshots/investigate-bl";
mkdirSync(OUT, { recursive: true });

test(`investigate ${HOST} — capture overflow + render diagnostics`, async ({ page }) => {
  test.setTimeout(180_000);

  await page.setViewportSize({ width: 1280, height: 900 });

  await page.goto(`/investigate?host=${encodeURIComponent(HOST)}`);
  await page.getByRole("heading", { name: /Per-host deep-dive/i }).waitFor();

  // Wait for the agent run's "done" pills (iterations + tools).
  await page.getByText(/iters?$/i).first().waitFor({ timeout: 150_000 });

  // Settle a beat for final layout.
  await page.waitForTimeout(800);

  // Full-page screenshot.
  await page.screenshot({ path: `${OUT}/full.png`, fullPage: true });

  // Diagnostics: find any element whose scrollWidth exceeds the viewport,
  // any element overflowing its parent, and dump the rendered markdown text
  // + tool-call summaries.
  const diag = await page.evaluate(() => {
    const vw = document.documentElement.clientWidth;

    type Overflow = {
      tag: string;
      cls: string;
      scrollWidth: number;
      clientWidth: number;
      overflowsViewport: boolean;
      sample: string;
    };

    const overflowing: Overflow[] = [];
    const all = document.querySelectorAll<HTMLElement>("body *");
    all.forEach((el) => {
      const sw = el.scrollWidth;
      const cw = el.clientWidth;
      const overflowsViewport = el.getBoundingClientRect().right > vw + 1;
      if (sw > cw + 1 || overflowsViewport) {
        // Skip explicitly-scrollable containers (we expect tables to scroll).
        const cs = getComputedStyle(el);
        const okScroll =
          cs.overflowX === "auto" || cs.overflowX === "scroll";
        if (okScroll && !overflowsViewport) return;
        overflowing.push({
          tag: el.tagName.toLowerCase(),
          cls: el.className?.toString().slice(0, 120) ?? "",
          scrollWidth: sw,
          clientWidth: cw,
          overflowsViewport,
          sample: (el.textContent ?? "").slice(0, 140).replace(/\s+/g, " "),
        });
      }
    });

    const md = document.querySelector<HTMLElement>("[data-print-target] .markdown");
    const mdHtml = md?.innerHTML ?? "";
    const mdText = md?.innerText ?? "";

    const tools: { name: string; statusText: string }[] = [];
    document.querySelectorAll<HTMLElement>("button[class*='font-mono']").forEach((b) => {
      const name = b.querySelector<HTMLElement>(".font-semibold")?.innerText ?? "";
      const status = b.querySelector<HTMLElement>("span:last-child")?.innerText ?? "";
      if (name) tools.push({ name, statusText: status });
    });

    return {
      vw,
      bodyScrollWidth: document.body.scrollWidth,
      overflowing: overflowing.slice(0, 25),
      overflowingCount: overflowing.length,
      mdLength: mdText.length,
      mdHtmlLength: mdHtml.length,
      mdTextSample: mdText.slice(0, 4000),
      mdHtmlSample: mdHtml.slice(0, 6000),
      tools,
    };
  });

  writeFileSync(`${OUT}/diagnostics.json`, JSON.stringify(diag, null, 2));

  // Also screenshot just the report panel.
  const panel = page.locator("[data-print-target]").first();
  if (await panel.count()) {
    await panel.screenshot({ path: `${OUT}/report-panel.png` });
  }

  // Tablet width — overflow regressions often show only narrower.
  await page.setViewportSize({ width: 900, height: 900 });
  await page.waitForTimeout(300);
  await page.screenshot({ path: `${OUT}/full-900.png`, fullPage: true });

  expect(diag.mdLength, "report panel should contain text").toBeGreaterThan(0);
});
