import { proxyBackend, routeParam, type RouteContext } from "@/lib/api-client";

export async function DELETE(_request: Request, context: RouteContext) {
  const id = await routeParam(context, "id");
  return proxyBackend(`/v1/users/invites/${id}`, { method: "DELETE" }, 204);
}
