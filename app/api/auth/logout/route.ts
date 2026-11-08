import { NextResponse } from "next/server";
import { getSession } from "@/lib/auth/session";

export async function POST(req: Request) {
  const session = await getSession();
  session.destroy();
  const url = new URL("/login", req.url);
  return NextResponse.redirect(url, { status: 303 });
}
