import { proxyBackend, proxyBackendJson } from "@/lib/api-client";

export async function GET() {
  return proxyBackend("/v1/red-team");
}

export async function POST(request: Request) {
  return proxyBackendJson(request, "/v1/red-team/runs", "POST", 201);
}
