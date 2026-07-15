import { NextRequest } from "next/server";
import { proxyBackend } from "@/lib/api-client";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const framework = searchParams.get("framework");
  const days = searchParams.get("days") || "30";
  const params: Record<string, string> = { days };
  if (framework) params.framework = framework;
  return proxyBackend("/v1/compliance-scores/history/trend", { params });
}
