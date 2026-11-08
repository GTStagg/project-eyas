import { test as setup, expect } from "@playwright/test";
import { sealData } from "iron-session";
import { mkdirSync, readFileSync, existsSync } from "node:fs";
import path from "node:path";

const AUTH_DIR = path.join(__dirname, ".auth");
const STATE_FILE = path.join(AUTH_DIR, "state.json");
const SESSION_COOKIE = "falcon_mcp_session";
const TTL_SECONDS = 7 * 24 * 60 * 60;

mkdirSync(AUTH_DIR, { recursive: true });

// Self-sufficient AUTH_SESSION_SECRET loader (.env.local then .env). Avoids the
// historical pitfall of `set -a; source .env.local; set +a` polluting the user's
// interactive shell with FALCON_*/ANTHROPIC_*/etc. exports that then override
// later-edited values for any process started in that shell.
// We only need AUTH_SESSION_SECRET to seal the cookie — read it once from
// disk and stop there, no broader leakage.
function loadEnvLocalSecret(): string | undefined {
  if (process.env.AUTH_SESSION_SECRET) return process.env.AUTH_SESSION_SECRET;
  // Read .env.local first (Next.js precedence: it overrides .env), then .env.
  for (const file of [".env.local", ".env"]) {
    const envPath = path.join(__dirname, "..", file);
    if (!existsSync(envPath)) continue;
    for (const raw of readFileSync(envPath, "utf8").split("\n")) {
      const line = raw.trim();
      if (!line || line.startsWith("#")) continue;
      const eq = line.indexOf("=");
      if (eq < 0) continue;
      const key = line.slice(0, eq).trim();
      if (key !== "AUTH_SESSION_SECRET") continue;
      let value = line.slice(eq + 1).trim();
      if (
        (value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))
      ) {
        value = value.slice(1, -1);
      }
      return value;
    }
  }
  return undefined;
}

/**
 * Seals a valid iron-session cookie using AUTH_SESSION_SECRET and saves it as
 * Playwright storageState. Other test projects reuse this state via
 * `use.storageState`.
 *
 * Why this approach (vs. driving the /login form): the form path requires
 * knowing the registered password, which changes per dev environment. Sealing
 * the cookie directly only needs the same secret the running server already
 * uses to verify it — bulletproof against password resets and password rotation.
 *
 * Requires AUTH_SESSION_SECRET to be exported in the shell that runs Playwright
 * (it must match what the dev server reads from .env / .env.local). If the
 * secret doesn't match, the test seal won't unseal at the server and the cookie
 * silently bounces to /login on every test.
 */
setup("authenticate", async ({ context, baseURL }) => {
  const secret = loadEnvLocalSecret();
  if (!secret || secret.length < 32) {
    throw new Error(
      "AUTH_SESSION_SECRET must be set (≥32 chars) in either the test shell " +
        "env or .env.local at the repo root. The setup loads .env.local " +
        "directly so no shell priming is needed — `npx playwright test` is " +
        "sufficient. If this error fires, check that .env.local exists and " +
        "contains a non-empty AUTH_SESSION_SECRET line.",
    );
  }

  const session = { authenticated: true as const, loginAt: new Date().toISOString() };
  const sealed = await sealData(session, { password: secret, ttl: TTL_SECONDS });

  const url = new URL(baseURL ?? "http://127.0.0.1:3000");
  await context.addCookies([
    {
      name: SESSION_COOKIE,
      value: sealed,
      domain: url.hostname,
      path: "/",
      httpOnly: true,
      sameSite: "Lax",
      expires: Math.floor(Date.now() / 1000) + TTL_SECONDS,
    },
  ]);

  // Sanity-check the cookie is accepted: hit a gated page and assert no
  // redirect to /login. Catches secret mismatch immediately rather than
  // letting every smoke test fail one-by-one.
  const page = await context.newPage();
  const resp = await page.goto("/", { waitUntil: "domcontentloaded" });
  expect(resp?.url(), "session cookie accepted").not.toMatch(/\/login/);
  await page.close();

  await context.storageState({ path: STATE_FILE });
});

export { STATE_FILE };
