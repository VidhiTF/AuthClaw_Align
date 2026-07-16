import { proxyBackend, routeParam, type RouteContext } from "@/lib/api-client";

export async function GET(_request: Request, context: RouteContext) {
  const id = await routeParam(context, "id");
  return proxyBackend(`/v1/evidence/${encodeURIComponent(id)}`);
}
