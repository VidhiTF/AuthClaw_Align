import { proxyBackendOptionalJson } from "@/lib/api-client";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  return proxyBackendOptionalJson(request, "/v1/audit-logs/export", "POST");
}
