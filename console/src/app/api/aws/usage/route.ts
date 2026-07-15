import { NextResponse } from "next/server";
import { backendFetch, getSessionContext } from "@/lib/api-client";

export const dynamic = "force-dynamic";

export async function GET() {
  const context = await getSessionContext();
  if ("response" in context) return context.response;
  try {
    return NextResponse.json(await backendFetch("/v1/aws/usage"));
  } catch {
    return NextResponse.json({
      tenant_id: "",
      daily_requests: 0,
      max_daily_requests: 100,
      daily_tokens: 0,
      max_daily_tokens: 50000,
      daily_cost_estimate: 0,
      max_daily_cost_usd: 1,
      last_reset: new Date().toISOString(),
      requests_remaining: 100,
      tokens_remaining: 50000,
    });
  }
}
