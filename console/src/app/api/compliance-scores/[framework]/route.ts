import { proxyBackend, routeParam, type RouteContext } from "@/lib/api-client";

export const dynamic = "force-dynamic";

export async function GET(_request: Request, context: RouteContext<{ framework: string }>) {
  const framework = await routeParam(context, "framework");
  return proxyBackend(`/v1/compliance-scores/${framework}`);
}
