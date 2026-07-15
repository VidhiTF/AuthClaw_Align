import { proxyBackendJson, routeParam, type RouteContext } from "@/lib/api-client";

export async function POST(
  request: Request,
  context: RouteContext
) {
  const id = await routeParam(context, "id");
  return proxyBackendJson(request, `/v1/api-keys/${id}/rotate`, "POST", 201);
}
