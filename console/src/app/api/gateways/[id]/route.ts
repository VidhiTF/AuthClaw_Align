import { proxyBackend, proxyBackendJson, routeParam, type RouteContext } from "@/lib/api-client";

export async function PUT(
  request: Request,
  context: RouteContext
) {
  const id = await routeParam(context, "id");
  return proxyBackendJson(request, `/v1/gateways/${id}`, "PUT");
}

export async function DELETE(
  _request: Request,
  context: RouteContext
) {
  const id = await routeParam(context, "id");
  return proxyBackend(`/v1/gateways/${id}`, { method: "DELETE" }, 204);
}
