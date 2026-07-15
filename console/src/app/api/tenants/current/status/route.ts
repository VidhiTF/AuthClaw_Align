import { proxyBackendJson } from "@/lib/api-client";

export async function PATCH(request: Request) {
  return proxyBackendJson(request, "/v1/tenants/current/status", "PATCH");
}
