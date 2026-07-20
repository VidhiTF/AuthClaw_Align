import { publicBackendPostJson, routeParam, RouteContext } from "@/lib/api-client";

export async function POST(request: Request, context: RouteContext<{ token: string }>) {
  const token = await routeParam(context, "token");
  return publicBackendPostJson(
    request,
    `/v1/trust-center/public/${encodeURIComponent(token)}/verify-access`,
    "Could not verify auditor email",
    "error"
  );
}
