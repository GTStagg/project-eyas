import { test, expect } from "@playwright/test";

const IR_PRIMER =
  "Run the agentic IR workflow on host `WIN-ACCT-01` (AID `abc123def4567890`). Load the playbook with extras_ir_workflow_playbook and proceed.";

test("hand-off renders a human-readable confirmation card, not raw jargon", async ({
  page,
}) => {
  await page.goto(`/?primer=${encodeURIComponent(IR_PRIMER)}`);

  // The card shows the plain-English summary…
  await expect(page.getByText("Pending action")).toBeVisible();
  await expect(
    page.getByText("Run guided incident response on WIN-ACCT-01"),
  ).toBeVisible();
  // …and a what/why line with no tool names.
  await expect(page.getByText(/Contains the host, hunts for persistence/)).toBeVisible();

  // The raw tool-name instruction is NOT visible until disclosed.
  await expect(page.getByText("extras_ir_workflow_playbook")).toHaveCount(0);

  await page.screenshot({ path: "tests/screenshots/primer-card-default.png", fullPage: false });

  // Disclose the precise instruction (transparency) and screenshot.
  await page.getByRole("button", { name: /Instructions/ }).click();
  await expect(page.getByText("extras_ir_workflow_playbook")).toBeVisible();
  await page.screenshot({ path: "tests/screenshots/primer-card-expanded.png", fullPage: false });

  // Cancel dismisses the card without running anything.
  await page.getByRole("button", { name: "Cancel" }).click();
  await expect(page.getByText("Pending action")).toHaveCount(0);
});

test("after Start, the user bubble shows the summary, not raw jargon", async ({
  page,
}) => {
  // Stub the agent turn so nothing real runs — we only care that the user
  // bubble renders the humanized summary with a details disclosure.
  await page.route("**/api/chat", (route) =>
    route.fulfill({
      status: 200,
      headers: { "content-type": "text/event-stream" },
      body: "event: ready\ndata: {}\n\nevent: text\ndata: Working on it.\n\n",
    }),
  );

  await page.goto(`/?primer=${encodeURIComponent(IR_PRIMER)}`);
  await page.getByRole("button", { name: /^Start$/ }).click();

  // The bubble shows the plain summary; the raw tool name is hidden until
  // "Show instructions" is expanded.
  await expect(
    page.getByText("Run guided incident response on WIN-ACCT-01"),
  ).toBeVisible();
  await expect(page.getByText("extras_ir_workflow_playbook")).toHaveCount(0);

  await page.getByRole("button", { name: "Show instructions" }).click();
  await expect(page.getByText("extras_ir_workflow_playbook")).toBeVisible();

  await page.screenshot({ path: "tests/screenshots/primer-bubble.png", fullPage: false });
});
