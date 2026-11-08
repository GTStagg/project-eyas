import { defineConfig } from "@playwright/test";
import path from "node:path";

const STORAGE_STATE = path.join(__dirname, "tests/.auth/state.json");

export default defineConfig({
  testDir: "./tests",
  timeout: 45_000,
  expect: { timeout: 8_000 },
  fullyParallel: false, // dev server is one process; serial is friendlier
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: "http://127.0.0.1:3000",
    actionTimeout: 8_000,
    navigationTimeout: 15_000,
    screenshot: "only-on-failure",
    video: "off",
    trace: "off",
  },
  projects: [
    {
      name: "setup",
      testMatch: /auth\.setup\.ts$/,
    },
    {
      name: "chromium",
      testIgnore: /auth\.setup\.ts$/,
      dependencies: ["setup"],
      use: { storageState: STORAGE_STATE },
    },
  ],
  // Reuses the dev server we already have running on :3000.
  webServer: {
    command: "npm run dev",
    url: "http://127.0.0.1:3000",
    reuseExistingServer: true,
    timeout: 120_000,
    stdout: "ignore",
    stderr: "pipe",
  },
});
