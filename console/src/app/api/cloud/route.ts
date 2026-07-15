import { proxyBackend, proxyBackendJson } from "@/lib/api-client";

export const dynamic = "force-dynamic";

export async function GET() {
  return proxyBackend("/v1/cloud/connectors");
}

export async function POST(request: Request) {
  return proxyBackendJson(request, "/v1/cloud/connectors", "POST", 201);
}
