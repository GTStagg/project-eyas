import { NextRequest, NextResponse } from "next/server";
import { sealData, unsealData } from "iron-session";

const SESSION_COOKIE = "falcon_mcp_session";
const TTL_SECONDS = 7 * 24 * 60 * 60;

const PUBLIC_PREFIXES = [
  "/login",
  "/register",
  "/api/auth/",
  // /api/healthz is a cheap public liveness probe (no upstream calls).
  // /api/health stays authenticated — it fans out to Anthropic + Falcon
  // probes, which we don't want exposed to unauthenticated callers.
  "/api/healthz",
  // /api/scheduled/* is called by an external scheduler/cron, not a browser
  // session — it carries no iron-session cookie, so the session redirect here
  // would make it permanently unreachable. The route enforces its own
  // SCHEDULER_TOKEN auth (x-scheduler-token / bearer), which is the real gate.
  "/api/scheduled/",
  "/_next/",
  "/favicon",
  "/icon",
  "/apple-icon",
  "/robots.txt",
  "/sitemap.xml",
];

type SessionData = {
  authenticated?: true;
  loginAt?: string;
};

function isPublic(pathname: string): boolean {
  if (pathname === "/login" || pathname === "/register") return true;
  return PUBLIC_PREFIXES.some((p) => pathname.startsWith(p));
}

// First-run registration is unauthenticated: whoever submits /register first
// sets the password and credentials. Only serve it to loopback host names,
// plus any hosts the operator lists in EYAS_ALLOWED_HOSTS (comma-separated,
// e.g. "eyas.example.com" behind a reverse proxy). This blocks DNS-rebinding
// pages, whose requests carry the attacker's host name, and LAN visitors who
// reach the instance by IP.
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);

function hostAllowedForRegister(hostHeader: string | null): boolean {
  if (!hostHeader) return false;
  const host = hostHeader.trim().toLowerCase();
  // Strip the port; bracketed IPv6 keeps its brackets.
  const name = host.startsWith("[") ? host.slice(0, host.indexOf("]") + 1) : host.split(":")[0];
  if (LOOPBACK_HOSTS.has(name) || name.endsWith(".localhost")) return true;
  const extra = (process.env.EYAS_ALLOWED_HOSTS ?? "")
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean);
  return extra.includes(name) || extra.includes(host);
}

// Cross-site request guard for state-changing API calls. The session cookie
// is SameSite=Lax, but "same site" ignores ports, so another app on
// localhost (or any page that can make a text/plain "simple" POST) could
// otherwise drive /api routes with the operator's cookie. Browsers send
// Sec-Fetch-Site on every request; when it's present only same-origin (or
// user-initiated "none") is accepted. Older clients without it are checked by
// comparing Origin with the request host. Requests carrying neither header
// aren't from a browser, so they can't ride the operator's cookie.
// /api/scheduled/* is exempt: external schedulers call it with SCHEDULER_TOKEN.
const UNSAFE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

function isCrossSiteApiWrite(req: NextRequest): boolean {
  const { pathname } = req.nextUrl;
  if (!pathname.startsWith("/api/") || pathname.startsWith("/api/scheduled/")) return false;
  if (!UNSAFE_METHODS.has(req.method)) return false;
  const site = req.headers.get("sec-fetch-site");
  if (site) return site !== "same-origin" && site !== "none";
  const origin = req.headers.get("origin");
  if (!origin) return false;
  let originHost: string;
  try {
    originHost = new URL(origin).host.toLowerCase();
  } catch {
    return true;
  }
  const hosts = [req.headers.get("x-forwarded-host"), req.headers.get("host")]
    .filter((h): h is string => Boolean(h))
    .map((h) => h.split(",")[0].trim().toLowerCase());
  return !hosts.includes(originHost);
}

export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;
  if (isCrossSiteApiWrite(req)) {
    return NextResponse.json({ error: "Cross-site request blocked." }, { status: 403 });
  }
  if (pathname === "/register" || pathname.startsWith("/register/")) {
    if (!hostAllowedForRegister(req.headers.get("host"))) {
      return new NextResponse(
        "Registration is only available from localhost. To register through another host name, add it to EYAS_ALLOWED_HOSTS.",
        { status: 403, headers: { "content-type": "text/plain; charset=utf-8" } },
      );
    }
  }
  if (isPublic(pathname)) {
    return NextResponse.next();
  }

  const secret = process.env.AUTH_SESSION_SECRET;
  if (!secret || secret.length < 32) {
    const url = req.nextUrl.clone();
    url.pathname = "/login";
    url.searchParams.set("err", "config");
    return NextResponse.redirect(url);
  }

  const sealed = req.cookies.get(SESSION_COOKIE)?.value;
  let session: SessionData | null = null;
  if (sealed) {
    try {
      session = await unsealData<SessionData>(sealed, { password: secret, ttl: TTL_SECONDS });
    } catch {
      session = null;
    }
  }

  if (!session?.authenticated) {
    const url = req.nextUrl.clone();
    url.pathname = "/login";
    url.searchParams.set("next", pathname + req.nextUrl.search);
    return NextResponse.redirect(url);
  }

  // Rolling renewal: re-seal and refresh cookie maxAge on each authenticated request.
  const res = NextResponse.next();
  const refreshed = await sealData(session, { password: secret, ttl: TTL_SECONDS });
  // Key Secure off the request scheme, not NODE_ENV: the standalone bundle
  // runs NODE_ENV=production over plain HTTP (http://127.0.0.1:3000), where a
  // Secure cookie is silently dropped and the rolling-renewal would log the
  // operator out. A TLS-terminating proxy sets x-forwarded-proto=https, so
  // real HTTPS deploys still get Secure.
  const proto = req.headers.get("x-forwarded-proto");
  const secure = proto ? proto.split(",")[0].trim() === "https" : false;
  res.cookies.set(SESSION_COOKIE, refreshed, {
    httpOnly: true,
    sameSite: "lax",
    secure,
    path: "/",
    maxAge: TTL_SECONDS,
  });
  return res;
}

// Excludes Next's optimized asset routes plus static-asset extensions in
// /public. Without the extension carve-out, image requests (e.g. icons
// referenced from /login + /register) hit the auth
// middleware on unauthenticated pages, redirect to /login, and the browser
// renders HTML in place of the image — visible as a broken-image placeholder
// on the very first paint of the wizard.
export const config = {
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico|.*\\.(?:png|jpg|jpeg|gif|svg|webp|ico|avif|woff|woff2|ttf|otf|eot)$).*)",
  ],
};
