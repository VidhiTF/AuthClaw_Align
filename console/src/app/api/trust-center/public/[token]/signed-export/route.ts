import { NextRequest } from "next/server";
import { publicBackendJson, routeParam, RouteContext } from "@/lib/api-client";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest, context: RouteContext<{ token: string }>) {
  const token = await routeParam(context, "token");
  const framework = request.nextUrl.searchParams.get("framework");
  const query = framework ? `?framework=${encodeURIComponent(framework)}` : "";
  const accessToken = request.headers.get("x-trust-center-access") || "";
  return publicBackendJson(
    `/v1/trust-center/public/${encodeURIComponent(token)}/signed-export${query}`,
    { cache: "no-store", headers: { "X-Trust-Center-Access": accessToken } },
    "Signed export request failed",
    "error",
    true
  );
}
