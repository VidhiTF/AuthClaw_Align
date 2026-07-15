import { NextResponse } from "next/server";
import { backendFetch, getSessionContext, proxyBackendWithSessionCheck } from "@/lib/api-client";

export const dynamic = "force-dynamic";

export async function GET() {
  const context = await getSessionContext();
  if ("response" in context) return context.response;
  try {
    return NextResponse.json(await backendFetch("/v1/aws/s3/documents"));
  } catch {
    return NextResponse.json([]);
  }
}

export async function POST() {
  return proxyBackendWithSessionCheck("/v1/aws/s3/sync", { method: "POST" });
}
