import { publicBackendJson, routeParam, RouteContext } from "@/lib/api-client";

export async function POST(_request: Request, context: RouteContext<{ token: string }>) {
  const token = await routeParam(context, "token");
  return publicBackendJson(
    `/v1/trust-center/public/${encodeURIComponent(token)}/request-access`,
    { method: "POST" },
    "Could not send auditor verification code",
    "error",
    true
  );
}
