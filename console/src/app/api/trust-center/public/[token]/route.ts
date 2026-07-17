import { publicBackendJson, routeParam, RouteContext } from "@/lib/api-client";

export const dynamic = "force-dynamic";

export async function GET(request: Request, context: RouteContext<{ token: string }>) {
  const token = await routeParam(context, "token");
  const accessToken = request.headers.get("x-trust-center-access") || "";
  return publicBackendJson(
    `/v1/trust-center/public/${encodeURIComponent(token)}`,
    { cache: "no-store", headers: { "X-Trust-Center-Access": accessToken } },
    "Trust Center request failed",
    "error",
    true
  );
}
