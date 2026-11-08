import "server-only";
import { cookies, headers } from "next/headers";
import { getIronSession, type SessionOptions } from "iron-session";

export type SessionData = {
  authenticated?: true;
  loginAt?: string;
};

const TTL_DAYS = 7;
const TTL_SECONDS = TTL_DAYS * 24 * 60 * 60;

function readSecret(): string {
  const secret = process.env.AUTH_SESSION_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error(
      "AUTH_SESSION_SECRET is required and must be at least 32 characters. Generate one with `openssl rand -hex 32`."
    );
  }
  return secret;
}

export const SESSION_COOKIE = "falcon_mcp_session";

// A Secure cookie is silently dropped by the browser over plain HTTP, which
// breaks login for the standalone bundle (NODE_ENV=production but served at
// http://127.0.0.1:3000). Key Secure off the actual request scheme instead:
// any TLS-terminating reverse proxy sets x-forwarded-proto=https, so real
// HTTPS deploys still get Secure; only direct-HTTP localhost relaxes it.
async function requestIsHttps(): Promise<boolean> {
  const proto = (await headers()).get("x-forwarded-proto");
  return proto ? proto.split(",")[0].trim() === "https" : false;
}

export function sessionOptions(secure: boolean): SessionOptions {
  return {
    password: readSecret(),
    cookieName: SESSION_COOKIE,
    ttl: TTL_SECONDS,
    cookieOptions: {
      httpOnly: true,
      sameSite: "lax",
      secure,
      path: "/",
      maxAge: TTL_SECONDS,
    },
  };
}

export async function getSession() {
  const store = await cookies();
  return getIronSession<SessionData>(store, sessionOptions(await requestIsHttps()));
}
