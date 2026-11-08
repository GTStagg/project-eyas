import { test, expect } from "@playwright/test";

// The conversation list is a pop-out drawer at every breakpoint (no longer a
// persistent desktop rail). On a desktop viewport it must be hidden on load,
// open via the header "Chats" button, and close via the backdrop / X / New.
test.describe("chat conversation pop-out drawer (desktop viewport)", () => {
  test.use({ viewport: { width: 1280, height: 800 } });

  test("hidden on load, opens + closes from header trigger", async ({ page }) => {
    const consoleErrors: string[] = [];
    page.on("console", (msg) => {
      if (msg.type() === "error") consoleErrors.push(msg.text());
    });
    page.on("pageerror", (err) => consoleErrors.push(`pageerror: ${err.message}`));

    await page.goto("/", { waitUntil: "domcontentloaded" });
    await page.waitForLoadState("networkidle");

    const drawer = page.getByRole("dialog");
    const heading = page.getByText("Conversations", { exact: true });
    const trigger = page.getByRole("button", { name: "Show conversations" });

    // (1) drawer NOT present on initial desktop load
    await expect(trigger).toBeVisible();
    await expect(drawer).toHaveCount(0);

    // Gate on hydration: clicking a starter prompt fills the composer, which
    // only works once React has attached handlers. Avoids racing the SSR'd
    // button with a click the dehydrated DOM would swallow.
    await page.getByRole("button", { name: /Summarize this week/ }).click();
    await expect(page.getByPlaceholder("Eyas…")).not.toHaveValue("");

    // (2)+(3) open it — overlay dialog + Conversations heading appear
    await trigger.click();
    await expect(drawer).toBeVisible();
    await expect(heading).toBeVisible();

    // (4a) backdrop click closes it
    await page.mouse.click(1200, 400); // far right, over the backdrop
    await expect(drawer).toHaveCount(0);

    // (4b) re-open, X closes it
    await trigger.click();
    await expect(drawer).toBeVisible();
    await page.getByRole("button", { name: "Close conversations" }).click();
    await expect(drawer).toHaveCount(0);

    // (5) New chat from inside the drawer closes it
    await trigger.click();
    await expect(drawer).toBeVisible();
    await drawer.getByRole("button", { name: /^New$/ }).click();
    await expect(drawer).toHaveCount(0);

    expect(consoleErrors).toEqual([]);
  });
});
