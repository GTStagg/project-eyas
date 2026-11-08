"use server";
import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { isRegistered, verify } from "@/lib/auth/store";
import { getSession } from "@/lib/auth/session";
import { clientKey, recordFailure, recordSuccess, retryAfterMs } from "@/lib/auth/login-throttle";

export type LoginState = { error?: string };

function safeNext(input: string | null): string {
  if (!input) return "/";
  // Same-origin paths only. Browsers treat "\" like "/", so "/\evil.com"
  // would otherwise redirect off-site.
  if (!input.startsWith("/") || input.startsWith("//") || input.includes("\\")) return "/";
  if (input.startsWith("/login") || input.startsWith("/register")) return "/";
  return input;
}

export async function loginAction(_prev: LoginState, formData: FormData): Promise<LoginState> {
  if (!(await isRegistered())) {
    redirect("/register");
  }
  const password = String(formData.get("password") ?? "");
  const next = safeNext(String(formData.get("next") ?? ""));

  const key = clientKey(await headers());
  const wait = retryAfterMs(key);
  if (wait > 0) {
    return { error: `Too many failed attempts. Try again in ${Math.ceil(wait / 1000)} seconds.` };
  }

  const ok = await verify(password);
  if (!ok) {
    recordFailure(key);
    return { error: "Invalid password." };
  }
  recordSuccess(key);

  const session = await getSession();
  session.authenticated = true;
  session.loginAt = new Date().toISOString();
  await session.save();
  redirect(next);
}
