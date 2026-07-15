import { NextRequest } from "next/server";
import { handleApiError, proxyBackend } from "@/lib/api-client";

export const dynamic = "force-dynamic";

export async function GET() {
  return proxyBackend("/v1/trust-center/shares");
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const origin = request.headers.get("origin") || new URL(request.url).origin;
    return proxyBackend("/v1/trust-center/shares", {
      method: "POST",
      headers: { "x-console-origin": origin },
      body: JSON.stringify(body),
    }, 201);
  } catch (error: unknown) {
    return handleApiError(error);
  }
}
