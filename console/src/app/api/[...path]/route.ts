import { NextResponse } from "next/server";
import { proxyBackend, proxyBackendJson, proxyBackendOptionalJson } from "@/lib/api-client";
import { resolveBffRoute, type BffMethod } from "@/lib/bff-routes";

export const dynamic = "force-dynamic";
type Context = { params: Promise<{ path: string[] }> };

async function forward(request: Request, context: Context, method: BffMethod) {
  const path = (await context.params).path.map(encodeURIComponent).join("/");
  const route = resolveBffRoute(method, path);
  if (!route) return NextResponse.json({ error: "Not found" }, { status: 404 });
  if (route.body === "json") return proxyBackendJson(request, route.backendPath, method, route.status);
  if (route.body === "optional-json") return proxyBackendOptionalJson(request, route.backendPath, method, route.status);
  const params = Object.fromEntries(new URL(request.url).searchParams);
  return proxyBackend(route.backendPath, { method, params }, route.status);
}

export const GET = (request: Request, context: Context) => forward(request, context, "GET");
export const POST = (request: Request, context: Context) => forward(request, context, "POST");
export const PUT = (request: Request, context: Context) => forward(request, context, "PUT");
export const PATCH = (request: Request, context: Context) => forward(request, context, "PATCH");
export const DELETE = (request: Request, context: Context) => forward(request, context, "DELETE");
