import { proxyBackendOptionalJson, routeParam, type RouteContext } from "@/lib/api-client";

export async function POST(request: Request, context: RouteContext) {
  const id = await routeParam(context, "id");
  return proxyBackendOptionalJson(request, `/v1/workflows/approvals/${id}/approve`, "POST");
}
