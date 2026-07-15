import { proxyBackend } from "@/lib/api-client";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const url = new URL(request.url);
  const params: Record<string, string> = {};
  for (const key of ["limit", "unread_only"]) {
    const value = url.searchParams.get(key);
    if (value) params[key] = value;
  }
  return proxyBackend("/v1/notifications", { params });
}
