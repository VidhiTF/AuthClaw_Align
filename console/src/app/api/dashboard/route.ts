import { NextResponse } from "next/server";
import { backendFetch, handleApiError } from "@/lib/api-client";

export const dynamic = "force-dynamic";

interface AuditMetricRecord {
  duration_ms?: number | null;
  duration?: number | null;
  timestamp?: string | null;
  created_at?: string | null;
}

interface AuditMetricResponse {
  total?: number;
  records?: AuditMetricRecord[];
}

export async function GET() {
  try {
    const [approvals, redactionMetrics] = await Promise.all([
      backendFetch("/v1/workflows/approvals") as Promise<Array<{ status: string }>>,
      backendFetch("/v1/redaction/metrics") as Promise<{ redactions_24h: number }>,
    ]);
    const openApprovals = approvals.filter((item) => item.status === "PENDING").length;
    const redactions24h = redactionMetrics.redactions_24h;

    let requestsPerSec: number | null = null;
    let p99LatencyMs: number | null = null;
    let totalRequests = 0;

    try {
      const logsData = await backendFetch("/v1/audit-logs?limit=100") as AuditMetricResponse;
      if (logsData.records && logsData.records.length > 0) {
        totalRequests = logsData.total || logsData.records.length;
        const latencies = logsData.records
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

        const timestamps = logsData.records
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
      p99LatencyMs,
    });
  } catch (error: unknown) {
    console.error("Dashboard API Error:", error);
    return handleApiError(error);
  }
}
