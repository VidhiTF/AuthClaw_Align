import { proxyBackend } from "@/lib/api-client";

export async function GET() {
  return proxyBackend("/v1/tenants/current");
}
