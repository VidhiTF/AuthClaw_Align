"use client";

import React, { useCallback, useEffect, useRef, useState } from "react";
import {
  Activity,
  EyeOff,
  Clock,
  ArrowUpRight,
  RefreshCw,
  UserRound,
} from "lucide-react";
import Link from "next/link";
import { calculationVersion } from "@/lib/trust-summary";
import { readinessLabel } from "@/lib/ui-format";

interface DashboardMetrics {
  status: "healthy" | "degraded" | "unavailable" | "unknown" | "not_applicable";
  sources: Record<string, { status: string }>;
  metricStates: Record<string, string>;
  openApprovals: number | null;
  redactions24h: number | null;
  totalRequests: number | null;
  requestsPerSec: number | null;
  p99LatencyMs: number | null;
}

interface FrameworkScore {
  calculation_version?: string;
  framework: "SOC2" | "GDPR" | "HIPAA";
  score: number | null;
  readiness_level: string;
  metrics: {
    evidence_count: number;
    audit_event_count: number;
    open_findings: number;
    critical_findings: number;
  };
}

interface ComplianceScoreState {
  calculation_version?: string;
  generated_at: string;
  overall_score: number | null;
  readiness_level: string;
  frameworks: FrameworkScore[];
}

interface RecentAuditRecord {
  record_id: string;
  timestamp: string;
  action: string;
  provider?: string;
  model?: string;
  reason?: string;
}

export default function OverviewPage() {
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [complianceScores, setComplianceScores] = useState<ComplianceScoreState | null>(null);
  const [scoresError, setScoresError] = useState<string | null>(null);
  const metricsRequest = useRef(0);
  const [recentActivity, setRecentActivity] = useState<RecentAuditRecord[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true); const [trafficRange, setTrafficRange] = useState(24); const trafficRangeRef = useRef(24);

  const fetchMetrics = useCallback(async (full = true, hours = trafficRangeRef.current) => {
    const request = ++metricsRequest.current;
    setMetrics(null);
    setError(null);
    setComplianceScores(null);
    setScoresError(null);
    try {
      if (full) setLoading(true);
      const results = await Promise.allSettled([
        fetch(`/api/dashboard?hours=${hours}`, { cache: "no-store", signal: AbortSignal.timeout(15000) }),
        fetch("/api/compliance-scores?persist_snapshot=false", { cache: "no-store", signal: AbortSignal.timeout(15000) }),
      ].map(async (pending) => {
        const response = await pending;
        if (response.status === 401) { window.location.href = "/login"; throw new Error("Session expired"); }
        if (!response.ok) throw new Error("Data unavailable");
        return response.json();
      }));
      if (request !== metricsRequest.current) return;
      const [dashboard, scores] = results;
      if (dashboard.status === "fulfilled") {
        setMetrics(dashboard.value);
        setRecentActivity(dashboard.value.recentActivity || []);
        setError(dashboard.value.status === "unavailable" ? "Telemetry unavailable for some dashboard sources. Successful observations remain visible." : null);
      } else { setMetrics(null); setRecentActivity([]); setError("Telemetry unavailable — dashboard source checks failed. Values are unknown."); }
      if (scores.status === "fulfilled") setComplianceScores(scores.value);
      else setScoresError("Current compliance assessment unavailable. Refresh to try again.");
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Could not retrieve real-time metrics";
      console.warn("Overview fetch metrics failed:", message);
      if (request === metricsRequest.current) {
        setMetrics(null); setRecentActivity([]); setComplianceScores(null);
        setError("Telemetry unavailable — source checks failed. Values are unknown.");
        setScoresError("Current compliance assessment unavailable. Refresh to try again.");
      }
    } finally {
      if (request === metricsRequest.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    const initialFetch = window.setTimeout(() => {
      void fetchMetrics();
    }, 0);
    const interval = setInterval(() => void fetchMetrics(false), 30000);
    return () => {
      window.clearTimeout(initialFetch);
      clearInterval(interval);
      metricsRequest.current += 1;
    };
  }, [fetchMetrics]);

  const frameworkLabels: Record<FrameworkScore["framework"], { name: string; color: string; desc: string }> = {
    SOC2: { name: "SOC 2 Type II", color: "bg-emerald-500", desc: "Security, confidentiality, monitoring, and remediation controls" },
    GDPR: { name: "GDPR", color: "bg-sky-500", desc: "Privacy-by-design, processing records, and security evidence" },
    HIPAA: { name: "HIPAA Safeguards", color: "bg-amber-400", desc: "Access, audit, integrity, and transmission safeguards" },
  };

  const complianceReadiness = complianceScores?.frameworks || [];
  const emptyActivity = metrics?.sources?.audit?.status === "healthy" ? "No recent audit activity."
    : metrics?.sources?.audit?.status === "unavailable" || error ? "Audit activity unavailable" : "Audit activity unknown";
  const telemetryStatus = error || scoresError ? "unavailable"
    : metrics?.status === "healthy" && (!complianceScores || complianceReadiness.some((framework) => framework.score == null)) ? "unknown"
    : metrics?.status || "unknown";

  return (
    <div className="ac-page ac-page-overview mx-auto max-w-none space-y-5">
      {error && <div role="alert" className="rounded-md border border-red-300 bg-red-50 p-4 text-red-800">{error}</div>}
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-extrabold tracking-tight text-[#0E1726]">
            Governance Overview
          </h1>
          <p className="text-[#6B7488] text-sm mt-1">
            Live view of AI traffic governance, redaction activity, and gateway telemetry.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => void fetchMetrics()}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#F5F7FA] hover:bg-[#EEF1F6] text-[#0E1726] border border-[#E6E9F0] text-xs font-semibold transition"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
          <div role="status" className="px-3 py-2 rounded-lg border text-xs font-semibold">
            {`Telemetry ${telemetryStatus}`}
          </div>
        </div>
      </div>

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">

        {/* Total Requests Card */}
        <div className="relative overflow-hidden rounded-[20px] bg-white border border-[#E6E9F0] p-6 shadow-xl hover:border-indigo-500/30 transition-all duration-300 group">
          <div className="absolute top-0 right-0 w-24 h-24 rounded-full bg-indigo-500/5 blur-[40px] pointer-events-none" />
          <div className="flex justify-between items-start">
            <div>
              <p className="text-[10px] uppercase tracking-widest font-bold text-[#6B7488]">Traffic Logged</p>
              <h3 className="text-2xl font-bold text-[#0E1726] mt-2">
                {loading ? "..." : metrics?.totalRequests ?? "Unknown"}
              </h3>
            </div>
            <div className="p-2.5 rounded-xl bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
              <Activity className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-4 flex items-center justify-between text-xs">
            <span className="text-[#6B7488]">Unique observed gateway requests · last {trafficRange}h</span>
            <Link href="/audit" className="text-indigo-400 hover:text-indigo-300 flex items-center gap-0.5 font-medium transition">
              Logs <ArrowUpRight className="w-3 h-3" />
            </Link>
          </div>
        </div>

        {/* PII Redactions Card */}
        <div className="relative overflow-hidden rounded-[20px] bg-white border border-[#E6E9F0] p-6 shadow-xl hover:border-emerald-500/30 transition-all duration-300">
          <div className="absolute top-0 right-0 w-24 h-24 rounded-full bg-emerald-500/5 blur-[40px] pointer-events-none" />
          <div className="flex justify-between items-start">
            <div>
              <p className="text-[10px] uppercase tracking-widest font-bold text-[#6B7488]">Redacted requests</p>
              <h3 className="text-2xl font-bold text-[#0E1726] mt-2">
                {loading ? "..." : metrics?.redactions24h ?? "Unknown"}
              </h3>
            </div>
            <div className="p-2.5 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
              <EyeOff className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-4 flex items-center justify-between text-xs">
            <span className="text-[#6B7488]">Masked or hashed ({trafficRange === 24 ? "last 24h" : trafficRange === 168 ? "last 7d" : "last 30d"})</span>
            <span className="text-[#6B7488]">Engine health not measured</span>
          </div>
        </div>

        {/* Open Approvals Card */}
        <div className="relative overflow-hidden rounded-[20px] bg-white border border-[#E6E9F0] p-6 shadow-xl hover:border-sky-500/30 transition-all duration-300">
          <div className="absolute top-0 right-0 w-24 h-24 rounded-full bg-sky-500/5 blur-[40px] pointer-events-none" />
          <div className="flex justify-between items-start">
            <div>
              <p className="text-[10px] uppercase tracking-widest font-bold text-[#6B7488]">Open Approvals</p>
              <h3 className="text-2xl font-bold text-[#0E1726] mt-2">
                {loading ? "..." : metrics?.openApprovals ?? "Unknown"}
              </h3>
            </div>
            <div className="p-2.5 rounded-xl bg-sky-500/10 border border-sky-500/20 text-sky-400">
              <UserRound className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-4 flex items-center justify-between text-xs text-[#6B7488]">
            <span>Awaiting operator decision</span>
            <Link href="/approvals" className="font-semibold text-[#6D28D9]">Review queue</Link>
          </div>
        </div>

        {/* P99 Latency Card */}
        <div className="relative overflow-hidden rounded-[20px] bg-white border border-[#E6E9F0] p-6 shadow-xl hover:border-purple-500/30 transition-all duration-300">
          <div className="absolute top-0 right-0 w-24 h-24 rounded-full bg-purple-500/5 blur-[40px] pointer-events-none" />
          <div className="flex justify-between items-start">
            <div>
              <p className="text-[10px] uppercase tracking-widest font-bold text-[#6B7488]">P99 Gateway Latency</p>
              <h3 className="text-2xl font-bold text-[#0E1726] mt-2">
                {loading ? (
                  "..."
                ) : metrics?.p99LatencyMs !== null && metrics?.p99LatencyMs !== undefined ? (
                  `${metrics.p99LatencyMs} ms`
                ) : (
                  <span className="text-sm font-medium text-[#6B7488]">{metrics?.metricStates?.p99LatencyMs === "unavailable" || !metrics && error ? "Unavailable" : "Unknown — no measurements"}</span>
                )}
              </h3>
            </div>
            <div className="p-2.5 rounded-xl bg-purple-500/10 border border-purple-500/20 text-purple-400">
              <Clock className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-4 flex items-center justify-between text-xs text-[#6B7488]">
            <span>99th percentile observed outcomes</span>
            <span>Proxy latency</span>
          </div>
        </div>

      </div>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,2.15fr)_minmax(18rem,.9fr)]">
        <div className="min-w-0 space-y-4">
          <section className="rounded-md border border-[#DCE1E9] bg-white p-5">
            <div className="flex items-start justify-between gap-4">
              <div><h3 className="text-lg font-bold">Traffic intelligence</h3><p className="mt-0.5 text-xs text-[#6B7488]">Governed AI requests, redactions, and policy actions.</p></div>
              <div className="flex shrink-0 overflow-hidden rounded-md border border-[#DCE1E9] text-[10px] font-semibold">{[[24,"24h"],[168,"7d"],[720,"30d"]].map(([hours,label]) => <button key={hours} type="button" aria-pressed={trafficRange === hours} onClick={() => { trafficRangeRef.current = Number(hours); setTrafficRange(Number(hours)); void fetchMetrics(false, Number(hours)); }} className={trafficRange === hours ? "bg-[#F1ECFE] px-4 py-2 text-[#6D28D9]" : "px-4 py-2 hover:bg-[#F5F7FA]"}>{label}</button>)}</div>
            </div>
            <div className="mt-5 grid min-h-44 place-items-center border-y border-[#EEF1F6] bg-[linear-gradient(#EEF1F6_1px,transparent_1px),linear-gradient(90deg,#EEF1F6_1px,transparent_1px)] bg-[size:100%_25%,12.5%_100%]">
              <div className="rounded-md bg-white/90 px-4 py-3 text-center text-xs text-[#6B7488]"><Activity className="mx-auto mb-2 h-5 w-5 text-[#6D28D9]"/>Historical traffic appears as real gateway telemetry accumulates.</div>
            </div>
            <div className="mt-4 grid grid-cols-3 gap-3 text-xs"><div><span className="text-[#6D28D9]">●</span> Total requests<strong className="mt-1 block text-sm">{metrics?.totalRequests ?? "Unknown"}</strong></div><div><span className="text-[#E9A93C]">●</span> Redactions<strong className="mt-1 block text-sm">{metrics?.redactions24h ?? "Unknown"}</strong></div><div><span className="text-[#94A3B8]">●</span> Throughput<strong className="mt-1 block text-sm">{metrics?.requestsPerSec == null ? "—" : `${metrics.requestsPerSec}/s`}</strong></div></div>
          </section>

          <section className="overflow-x-auto rounded-md border border-[#DCE1E9] bg-white">
            <div className="flex items-center justify-between px-5 py-4"><div><h3 className="text-lg font-bold">Compliance readiness</h3><p className="text-xs text-[#6B7488]">Scores require current reviewed evidence. Unknown means evidence is insufficient; 0% means a reviewed control failed. Activity counts cannot establish compliance.</p></div><Link href="/compliance" className="text-xs font-semibold text-[#6D28D9]">View details →</Link></div>
            {complianceScores && <p className="px-5 pb-3 text-[10px] text-[#6B7488]">As of {new Date(complianceScores.generated_at).toLocaleString()} · Calculation version: {calculationVersion(complianceScores.calculation_version)}{calculationVersion(complianceScores.calculation_version) === "legacy_unversioned" && " · Legacy results do not establish current evidence qualification."}</p>}
            <table className="w-full text-left text-xs"><thead><tr><th className="px-5 py-2">Framework</th><th className="px-4 py-2">Status</th><th className="px-4 py-2">Qualified evidence coverage</th><th className="px-4 py-2">Activity records</th><th className="px-5 py-2">Open issues</th></tr></thead><tbody>{complianceReadiness.length === 0 ? <tr><td colSpan={5} className="px-5 py-8 text-center text-[#6B7488]" role={scoresError ? "alert" : "status"}>{scoresError || (loading ? "Loading current compliance assessment…" : "Current compliance assessment unknown")}</td></tr> : complianceReadiness.map((framework) => { const meta = frameworkLabels[framework.framework]; return <tr key={framework.framework} className="border-t border-[#EEF1F6]"><td className="px-5 py-3 font-semibold">{meta.name}<span className="mt-1 block text-[10px] font-normal text-[#6B7488]">{calculationVersion(framework.calculation_version)}</span></td><td className="px-4 py-3 text-[#475069]">{readinessLabel(framework.readiness_level)}</td><td className="px-4 py-3"><div className="flex items-center gap-2"><span>{framework.score == null ? "Unknown" : `${framework.score}%`}</span>{framework.score != null && <span className="h-1.5 w-20 overflow-hidden rounded-full bg-[#EEF1F6]"><span className="block h-full bg-[#6D28D9]" style={{width:`${framework.score}%`}}/></span>}</div></td><td className="px-4 py-3">{framework.metrics.evidence_count}</td><td className="px-5 py-3">{framework.metrics.open_findings}</td></tr>; })}</tbody></table>
          </section>
        </div>

        <aside className="rounded-md border border-[#DCE1E9] bg-white p-5">
          <div className="flex items-center justify-between"><h3 className="text-lg font-bold">Recent activity</h3><Link href="/audit" className="text-xs font-semibold text-[#6D28D9]">View all →</Link></div>
          <div className="mt-3 divide-y divide-[#EEF1F6]">{recentActivity.length === 0 ? <div className="py-10 text-center text-xs text-[#6B7488]">{emptyActivity}</div> : recentActivity.map((record, index) => <Link href="/audit" key={record.record_id} className="flex gap-3 py-3"><span className={`mt-1 h-2.5 w-2.5 shrink-0 rounded-full ${index % 3 === 0 ? "bg-[#6D28D9]" : index % 3 === 1 ? "bg-emerald-500" : "bg-[#E9A93C]"}`}/><span className="min-w-0"><strong className="block truncate text-xs">{record.action.replaceAll("_", " ")}</strong><span className="mt-0.5 block truncate text-[10px] text-[#6B7488]">{record.provider || "AuthClaw"}{record.model ? ` · ${record.model}` : ""}</span></span><time className="ml-auto shrink-0 text-[9px] text-[#6B7488]">{new Date(record.timestamp).toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"})}</time></Link>)}</div>
        </aside>
      </div>
    </div>
  );
}
