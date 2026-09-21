import { NextResponse } from "next/server";
import { getSessionContext, handleApiError } from "@/lib/api-client";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  try {
    const context = await getSessionContext();
    if ("response" in context) return context.response;
    const hours = Math.max(1, Math.min(720, Math.trunc(Number(new URL(request.url).searchParams.get("hours"))) || 24));
    const headers = { Authorization: `Bearer ${context.session.apiKey}` };
    const apiUrl = process.env.API_URL || "http://localhost:8000";
    const results = await Promise.allSettled([
      "/v1/workflows/approvals", `/v1/audit-logs/metrics?hours=${hours}`, "/v1/audit-logs?limit=8",
    ].map(async (path) => {
      const response = await fetch(`${apiUrl}${path}`, { headers, cache: "no-store", signal: AbortSignal.timeout(15000) });
      if (!response.ok) throw new Error("Dashboard source unavailable");
      return response.json();
    }));
    const [approvals, gateway, audit] = results.map((result) => result.status === "fulfilled" ? result.value : null);
    const approvalValid = Array.isArray(approvals) && approvals.every((item) => typeof item?.status === "string");
    const metricNames = ["totalRequests", "redactions24h", "requestsPerSec", "p99LatencyMs"] as const;
    const gatewayValid = gateway?.source === "postgres" && typeof gateway.complete === "boolean"
      && ["healthy", "degraded", "unknown", "unavailable", "not_applicable"].includes(gateway.status)
      && [gateway.windowStart, gateway.windowEnd].every((value) => typeof value === "string" && Number.isFinite(Date.parse(value)))
      && metricNames.every((name) => gateway[name] === null || (typeof gateway[name] === "number" && Number.isFinite(gateway[name]) && gateway[name] >= 0));
    const auditValid = Array.isArray(audit?.records) && audit.records.every((record: { record_id?: string; action?: string; timestamp?: string }) =>
      typeof record?.record_id === "string" && typeof record.action === "string" && typeof record.timestamp === "string" && Number.isFinite(Date.parse(record.timestamp)));
    const generatedAt = new Date().toISOString();
    const sources = {
      approvals: { status: approvalValid ? "healthy" : "unavailable", source: "postgres", observedAt: generatedAt },
      gateway: { status: !gatewayValid ? "unavailable" : gateway.status, source: "postgres", observedAt: gatewayValid ? gateway.windowEnd : generatedAt },
      audit: { status: !auditValid ? "unavailable" : audit.source === "postgres" ? "healthy" : "unknown", source: auditValid ? audit.source : null, observedAt: generatedAt },
    };
    const metrics = Object.fromEntries(metricNames.map((name) => [name, gatewayValid && gateway.complete && gateway.status === "healthy" ? gateway[name] : null]));
    const metricStates = {
      openApprovals: sources.approvals.status,
      ...Object.fromEntries(metricNames.map((name) => [name, sources.gateway.status !== "healthy" ? sources.gateway.status : metrics[name] === null ? "unknown" : "healthy"])),
    };
    const states = [...Object.values(sources).map((source) => source.status), ...Object.values(metricStates)];
    // Failures outrank missing observations; a successful source never masks another's failure.
    const status = ["unavailable", "degraded", "unknown", "healthy", "not_applicable"].find((state) => states.includes(state)) || "unknown";
    return NextResponse.json({
      status, sources, metricStates, generatedAt,
      coverageReason: gatewayValid && !gateway.complete ? (typeof gateway.reason === "string" ? gateway.reason : "Gateway collection coverage is unverified.") : null,
      complete: gatewayValid ? gateway.complete : false,
      windowStart: gatewayValid ? gateway.windowStart : null, windowEnd: gatewayValid ? gateway.windowEnd : null,
      openApprovals: approvalValid ? approvals.filter((item) => item.status === "PENDING").length : null,
      ...metrics, recentActivity: auditValid ? audit.records.slice(0, 8) : [],
    });
  } catch (error: unknown) {
    console.error("Dashboard API Error:", error);
    return handleApiError(error);
  }
}
