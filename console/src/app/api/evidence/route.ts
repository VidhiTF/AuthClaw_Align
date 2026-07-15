import { proxyBackend } from "@/lib/api-client";

export async function GET(request: Request) {
  const searchParams = new URL(request.url).searchParams;
  const params: Record<string, string> = {};
  for (const key of ["page", "page_size", "framework", "evidence_type", "severity"]) {
    const value = searchParams.get(key);
    if (value) params[key] = value;
  }
  return proxyBackend("/v1/evidence", { params });
}
