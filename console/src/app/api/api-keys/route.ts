import { proxyBackend, proxyBackendJson } from "@/lib/api-client";

export async function GET() {
  return proxyBackend("/v1/api-keys");
}

export async function POST(request: Request) {
  return proxyBackendJson(request, "/v1/api-keys", "POST", 201);
}
