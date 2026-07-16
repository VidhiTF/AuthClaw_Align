import { publicBackendJson, routeParam, RouteContext } from "@/lib/api-client";

export const dynamic = "force-dynamic";

export async function GET(_request: Request, context: RouteContext<{ token: string }>) {
  const token = await routeParam(context, "token");
  return publicBackendJson(
    `/v1/trust-center/public/${encodeURIComponent(token)}`,
    { cache: "no-store" },
    "Trust Center request failed",
    "error",
    true
  );
}
