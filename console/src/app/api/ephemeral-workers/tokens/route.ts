import { proxyBackend, proxyBackendJson } from "@/lib/api-client";

export const dynamic = "force-dynamic";

export async function GET() {
  return proxyBackend("/v1/ephemeral-workers/tokens");
}

export async function POST(request: Request) {
  return proxyBackendJson(request, "/v1/ephemeral-workers/tokens", "POST", 201);
}
