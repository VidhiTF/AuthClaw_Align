import { agentFetch, handleApiError } from "@/lib/api-client";
import { NextResponse } from "next/server";

export async function GET() {
  try {
    const [connectors, findings] = await Promise.all([
      agentFetch("/remediation/connectors"),
      agentFetch("/remediation/findings"),
    ]);
    return NextResponse.json({
      connectors: Array.isArray(connectors) ? connectors : [],
      findings: Array.isArray(findings) ? findings : [],
    });
  } catch (error: unknown) {
    return handleApiError(error);
  }
}
