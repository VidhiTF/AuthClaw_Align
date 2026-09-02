import { NextResponse } from "next/server";
import { backendFetch, handleApiError, proxyBackendJson } from "@/lib/api-client";

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const id = searchParams.get("id");

    if (id) {
      return NextResponse.json(await backendFetch(`/v1/policies/${id}`));
    }

    const data = await backendFetch("/v1/policies");
    return NextResponse.json(data);
  } catch (error: unknown) {
    return handleApiError(error);
  }
}

export async function POST(request: Request) {
  return proxyBackendJson(request, "/v1/policies", "POST", 201);
}
