import { NextResponse } from "next/server";
import { getBuildInfo } from "@/lib/build-info";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const info = await getBuildInfo();
  return NextResponse.json(info);
}
