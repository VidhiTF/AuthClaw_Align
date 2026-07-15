import { proxyBackend, proxyBackendJson } from "@/lib/api-client";

export async function GET() {
  return proxyBackend("/v1/provider-credentials");
}

export async function POST(request: Request) {
  return proxyBackendJson(request, "/v1/provider-credentials", "POST", 201);
}
