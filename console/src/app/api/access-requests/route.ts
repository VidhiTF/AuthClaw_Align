import { proxyBackend, publicBackendPostJson } from "@/lib/api-client";

export async function GET(request: Request) {
  const params = Object.fromEntries(new URL(request.url).searchParams);
  return proxyBackend("/api/public/v1/access-requests", {
    method: "GET",
    params,
  });
}

export async function POST(request: Request) {
  return publicBackendPostJson(
    request,
    "/api/public/v1/access-requests",
    "Unable to submit request"
  );
}
