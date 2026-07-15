import { proxyBackend } from "@/lib/api-client";

export const dynamic = "force-dynamic";

export async function POST() {
  return proxyBackend("/v1/auth/oidc/admin-config/test", { method: "POST" });
}
