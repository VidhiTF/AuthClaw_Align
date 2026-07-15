import { proxyBackend, proxyBackendJson } from "@/lib/api-client";

export const dynamic = "force-dynamic";

export async function GET() {
  return proxyBackend("/v1/auth/oidc/admin-config");
}

export async function PUT(request: Request) {
  return proxyBackendJson(request, "/v1/auth/oidc/admin-config", "PUT");
}
