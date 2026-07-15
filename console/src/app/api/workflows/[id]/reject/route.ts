import { proxyBackend, routeParam, RouteContext } from "@/lib/api-client";

export async function POST(_request: Request, context: RouteContext) {
  const id = await routeParam(context, "id");
  return proxyBackend(`/v1/workflows/${id}/reject`, { method: "POST" });
}
