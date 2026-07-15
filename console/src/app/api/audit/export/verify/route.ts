import { proxyBackendJson } from "@/lib/api-client";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  return proxyBackendJson(request, "/v1/audit-logs/export/verify", "POST");
}
