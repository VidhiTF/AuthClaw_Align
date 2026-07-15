import { proxyBackend } from "@/lib/api-client";

export async function POST() {
  return proxyBackend("/v1/users/me/mfa/disable", { method: "POST" });
}
