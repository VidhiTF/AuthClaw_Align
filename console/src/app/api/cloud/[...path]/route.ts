import { proxyBackendOptionalJson, proxyBackend } from "@/lib/api-client";

export const dynamic = "force-dynamic";

type CloudRouteContext = { params: Promise<{ path?: string[] }> };

async function cloudPath(context: CloudRouteContext) {
  const params = await context.params;
  return `/v1/cloud/connectors/${(params.path || []).join("/")}`;
}

export async function GET(_request: Request, context: CloudRouteContext) {
  return proxyBackend(await cloudPath(context));
}

export async function POST(request: Request, context: CloudRouteContext) {
  return proxyBackendOptionalJson(request, await cloudPath(context), "POST");
}

export async function DELETE(_request: Request, context: CloudRouteContext) {
  return proxyBackend(await cloudPath(context), { method: "DELETE" }, 204);
}
