import { proxyBackendJson } from "@/lib/api-client";

export async function POST(request: Request) {
  return proxyBackendJson(request, "/v1/policies/simulate", "POST");
}
