import { publicBackendPostJson } from "@/lib/api-client";

export async function POST(request: Request) {
  return publicBackendPostJson(
    request,
    "/api/public/v1/access-requests",
    "Unable to submit request"
  );
}
