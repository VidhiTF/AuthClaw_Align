import { NextResponse } from "next/server";
import { backendFetch, handleApiError } from "@/lib/api-client";

async function proxyRequest(request: Request, method: string) {
  try {
    const { searchParams } = new URL(request.url);
    const path = searchParams.get("path");

    if (!path) {
      return NextResponse.json({ error: "Missing path parameter" }, { status: 400 });
    }

    const params: Record<string, string> = {};
    searchParams.forEach((value, key) => {
      if (key !== "path") {
        params[key] = value;
      }
    });

    const options: RequestInit & { params?: Record<string, string> } = {
      method,
      params,
    };

    if (method !== "GET" && method !== "HEAD") {
      try {
        const body = await request.json();
        options.body = JSON.stringify(body);
      } catch {
        // ignore body parse error if no body provided
      }
    }

    const data = await backendFetch(path, options);
    return NextResponse.json(data || {});
  } catch (error: unknown) {
    return handleApiError(error);
  }
}

export const GET = (request: Request) => proxyRequest(request, "GET");
export const POST = (request: Request) => proxyRequest(request, "POST");
export const PATCH = (request: Request) => proxyRequest(request, "PATCH");
export const DELETE = (request: Request) => proxyRequest(request, "DELETE");
