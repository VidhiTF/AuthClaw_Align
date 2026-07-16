import { proxyBackend, proxyBackendJson } from "@/lib/api-client";

export async function GET() {
  return proxyBackend("/v1/gateways");
}

export async function POST(request: Request) {
  return proxyBackendJson(request, "/v1/gateways", "POST", 201);
}
