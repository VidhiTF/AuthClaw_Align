import { publicBackendPostJson } from "@/lib/api-client";

export async function POST(request: Request) {
  return publicBackendPostJson(
    request,
    "/v1/auth/password-reset/request",
    "Password reset request failed",
    "detail",
    (body) => {
      const tenantName = body.tenantName ?? body.tenant_name;
      return {
        email: body.email,
        tenant_name: typeof tenantName === "string" ? tenantName.trim() || null : null,
      };
    }
  );
}
