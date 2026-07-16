import { NextResponse } from "next/server";
import { backendFetch, handleApiError } from "@/lib/api-client";
import { getErrorMessage } from "@/lib/errors";

export async function GET() {
  try {
    const data = await backendFetch("/v1/policies/active");
    return NextResponse.json(data);
  } catch (error: unknown) {
    const message = getErrorMessage(error, "Failed to load active policy");
    if (message.includes("Unauthorized")) {
      return handleApiError(error);
    }
    // Return empty string or 404 cleanly so UI doesn't crash if no policies exist yet
    return NextResponse.json({ error: message }, { status: 404 });
  }
}
