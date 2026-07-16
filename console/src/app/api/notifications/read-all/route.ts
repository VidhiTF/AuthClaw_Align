import { proxyBackend } from "@/lib/api-client";

export async function POST() {
  return proxyBackend("/v1/notifications/read-all", { method: "POST" });
}
