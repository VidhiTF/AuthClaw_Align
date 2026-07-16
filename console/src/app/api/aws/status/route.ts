import { proxyBackendWithSessionCheck } from "@/lib/api-client";

export const dynamic = "force-dynamic";

export async function GET() {
  return proxyBackendWithSessionCheck("/v1/aws/status");
}
