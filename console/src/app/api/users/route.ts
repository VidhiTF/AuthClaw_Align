import { proxyBackend, proxyBackendJson } from "@/lib/api-client";

export async function GET() {
  return proxyBackend("/v1/users");
}

export async function POST(request: Request) {
  return proxyBackendJson(request, "/v1/users", "POST", 201);
}
