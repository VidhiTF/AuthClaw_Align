import { NextResponse } from "next/server";
import { backendFetch, handleApiError, proxyBackendJson } from "@/lib/api-client";

export async function GET() {
  try {
    const [workflows, approvals] = await Promise.all([
      backendFetch("/v1/workflows"),
      backendFetch("/v1/workflows/approvals"),
    ]);
    return NextResponse.json({ workflows, approvals });
  } catch (error: unknown) {
    return handleApiError(error);
  }
}

export async function POST(request: Request) {
  return proxyBackendJson(request, "/v1/workflows", "POST", 201);
}
