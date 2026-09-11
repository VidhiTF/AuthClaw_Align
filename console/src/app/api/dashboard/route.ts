import { NextResponse } from "next/server";
import { getSessionContext, handleApiError } from "@/lib/api-client";

export const dynamic = "force-dynamic";

interface AuditMetricRecord { action?: string | null;
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
    const openApprovals = approvals.filter((item) => item.status === "PENDING").length;
    const redactions24h = (auditMetrics.records || []).filter((record) => record.action === "redact" && new Date(record.timestamp || record.created_at || "").getTime() >= Date.now() - hours * 3600000).length;

    let requestsPerSec: number | null = null;
    let p99LatencyMs: number | null = null;
    let totalRequests = 0;

    try {
      const logsData = auditMetrics;
      const records = (logsData.records || []).filter((record) => new Date(record.timestamp || record.created_at || "").getTime() >= Date.now() - hours * 3600000); if (records.length > 0) {
        totalRequests = records.length;
        const latencies = records
          .map((record) => record.duration_ms || record.duration)
          .filter((latency): latency is number => latency !== undefined && latency !== null)
          .sort((a: number, b: number) => a - b);

        if (latencies.length > 0) {
          const p99Index = Math.min(
            latencies.length - 1,
            Math.ceil(latencies.length * 0.99) - 1
          );
          p99LatencyMs = latencies[p99Index];
        }

        const timestamps = records
          .map((record) => new Date(record.timestamp || record.created_at || "").getTime())
          .filter((t: number) => !isNaN(t));

        if (timestamps.length > 1) {
          const maxTime = Math.max(...timestamps);
          const minTime = Math.min(...timestamps);
          const diffSeconds = (maxTime - minTime) / 1000;
          if (diffSeconds > 0) {
            requestsPerSec = Number((timestamps.length / diffSeconds).toFixed(2));
          }
        }
      }
    } catch (err) {
      console.warn("Failed to fetch traffic metrics from ClickHouse/Postgres audit logs:", err);
    }

    return NextResponse.json({
      openApprovals,
      redactions24h,
      totalRequests,
      requestsPerSec,
      p99LatencyMs, recentActivity: (auditMetrics.records || []).slice(0, 8),
    });
  } catch (error: unknown) {
    console.error("Dashboard API Error:", error);
    return handleApiError(error);
  }
}
