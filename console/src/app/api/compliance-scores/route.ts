import { proxyBackend } from "@/lib/api-client";

export const dynamic = "force-dynamic";

export async function GET() {
  return proxyBackend("/v1/compliance-scores");
}
