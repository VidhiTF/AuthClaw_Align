import { publicBackendPostJson } from "@/lib/api-client";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  return publicBackendPostJson(
    request,
    "/v1/trust-center/public/verify",
    "Verification request failed",
    "error",
    (body) => body,
    { cache: "no-store" },
    true
  );
}
