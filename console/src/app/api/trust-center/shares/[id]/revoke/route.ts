import { proxyBackend, routeParam, type RouteContext } from "@/lib/api-client";

export const dynamic = "force-dynamic";

export async function POST(_request: Request, context: RouteContext) {
  const id = await routeParam(context, "id");
  return proxyBackend(`/v1/trust-center/shares/${id}/revoke`, { method: "POST" });
}
