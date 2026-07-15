import { publicBackendPostJson } from "@/lib/api-client";

export async function POST(request: Request) {
  return publicBackendPostJson(request, "/v1/onboarding/resend", "Onboarding OTP resend failed");
}
