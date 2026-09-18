import { NextResponse } from "next/server";
import { getSessionContext, handleApiError } from "@/lib/api-client";

export const dynamic = "force-dynamic";

interface AuditMetricRecord { action?: string | null;
  actor_type?: string | null;
  request_id?: string | null;
  idempotency_key?: string | null;
  duration_ms?: number | null;
  duration?: number | null;
  timestamp?: string | null;
  created_at?: string | null;
}

interface AuditMetricResponse {
  total?: number;
  records?: AuditMetricRecord[];
}

export async function GET(request: Request) {
  try { const context = await getSessionContext(); if ("response" in context) return context.response;
    const hours = Math.max(1, Math.min(720, Number(new URL(request.url).searchParams.get("hours")) || 24)); const headers = { Authorization: `Bearer ${context.session.apiKey}` }; const apiUrl = process.env.API_URL || "http://localhost:8000";
    const [approvalsResponse, auditResponse] = await Promise.all([fetch(`${apiUrl}/v1/workflows/approvals`, { headers, cache: "no-store", signal: AbortSignal.timeout(15000) }), fetch(`${apiUrl}/v1/audit-logs?limit=100`, { headers, cache: "no-store", signal: AbortSignal.timeout(15000) })]);
    if (!approvalsResponse.ok || !auditResponse.ok) throw new Error("Dashboard backend request failed");
    const [approvals, auditMetrics] = await Promise.all([approvalsResponse.json() as Promise<Array<{ status: string }>>, auditResponse.json() as Promise<AuditMetricResponse>]);
    if (!Array.isArray(approvals) || approvals.some((item) => typeof item?.status !== "string") || !Array.isArray(auditMetrics.records)) throw new Error("Dashboard source payload unavailable");
    if (auditMetrics.records.some((record) => !Number.isFinite(new Date(record?.timestamp || record?.created_at || "").getTime()))) throw new Error("Audit timestamps unavailable");
    const openApprovals = approvals.filter((item) => item.status === "PENDING").length;
    const records = auditMetrics.records.filter((record) => new Date(record.timestamp || record.created_at || "").getTime() >= Date.now() - hours * 3600000);
    const redactions24h = records.filter((record) => record.action === "redact").length;
    let requestsPerSec: number | null = null;
    let p99LatencyMs: number | null = null;
    const totalRequests = records.length;
    if (records.length > 0) {
      const latencies = records
        // Provider outcomes measure the full request; decision/admin events can carry placeholder zero.
        .filter((record) => record.actor_type === "gateway" && record.request_id && record.idempotency_key === `gateway:${record.request_id}:provider_outcome`)
        .map((record) => record.duration_ms ?? record.duration)
        .filter((latency): latency is number => typeof latency === "number" && Number.isFinite(latency) && latency >= 0)
        .sort((a: number, b: number) => a - b);
      if (latencies.length > 0) {
        p99LatencyMs = latencies[Math.ceil(latencies.length * 0.99) - 1];
      }
      const timestamps = records.map((record) => new Date(record.timestamp || record.created_at || "").getTime());
      const diffSeconds = (Math.max(...timestamps) - Math.min(...timestamps)) / 1000;
      if (diffSeconds > 0) {
        requestsPerSec = Number((timestamps.length / diffSeconds).toFixed(2));
      }
    }

    return NextResponse.json({
      status: "healthy", sampleLimit: 100, generatedAt: new Date().toISOString(),
      openApprovals,
      redactions24h,
      totalRequests,
      requestsPerSec,
      p99LatencyMs, recentActivity: auditMetrics.records.slice(0, 8),
    });
  } catch (error: unknown) {
    console.error("Dashboard API Error:", error);
    return handleApiError(error);
  }
}
