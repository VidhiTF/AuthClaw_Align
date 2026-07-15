import { proxyBackend, routeParam, type RouteContext } from "@/lib/api-client";

export async function DELETE(_request: Request, context: RouteContext) {
  const id = await routeParam(context, "id");
  return proxyBackend(`/v1/provider-credentials/${id}`, { method: "DELETE" }, 204);
}
