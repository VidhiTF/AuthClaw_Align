"use client";

import React, { useEffect, useState } from "react";
import {
  ShieldCheck,
  Activity,
  EyeOff,
  Clock,
  Award,
  ArrowUpRight,
  RefreshCw,
  CheckCircle2,
} from "lucide-react";
import Link from "next/link";

interface DashboardMetrics {
  openApprovals: number;
  redactions24h: number;
  totalRequests: number;
  requestsPerSec: number | null;
  p99LatencyMs: number | null;
}

interface FrameworkScore {
  framework: "SOC2" | "GDPR" | "HIPAA";
  score: number;
  readiness_level: string;
  metrics: {
    evidence_count: number;
    audit_event_count: number;
    open_findings: number;
    critical_findings: number;
  };
}

interface ComplianceScoreState {
  overall_score: number;
  readiness_level: string;
  frameworks: FrameworkScore[];
}

export default function OverviewPage() {
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [complianceScores, setComplianceScores] = useState<ComplianceScoreState | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchMetrics = async () => {
    try {
      setLoading(true);
      const [dashboardRes, scoresRes] = await Promise.all([
        fetch("/api/dashboard"),
        fetch("/api/compliance-scores?persist_snapshot=false"),
      ]);
      if (dashboardRes.status === 401 || scoresRes.status === 401) {
        window.location.href = "/login";
        return;
      }
      if (!dashboardRes.ok) throw new Error("Failed to load metrics");
      const data = await dashboardRes.json();
      setMetrics(data);
      if (scoresRes.ok) {
        setComplianceScores(await scoresRes.json());
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Could not retrieve real-time metrics";
      console.warn("Overview fetch metrics failed:", message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const initialFetch = window.setTimeout(() => {
      void fetchMetrics();
    }, 0);
    const interval = setInterval(fetchMetrics, 5000);
    return () => {
      window.clearTimeout(initialFetch);
      clearInterval(interval);
    };
  }, []);

  const frameworkLabels: Record<FrameworkScore["framework"], { name: string; color: string; desc: string }> = {
    SOC2: { name: "SOC 2 Type II", color: "bg-emerald-500", desc: "Security, confidentiality, monitoring, and remediation controls" },
    GDPR: { name: "GDPR", color: "bg-sky-500", desc: "Privacy-by-design, processing records, and security evidence" },
    HIPAA: { name: "HIPAA Safeguards", color: "bg-amber-400", desc: "Access, audit, integrity, and transmission safeguards" },
  };

  const complianceReadiness = complianceScores?.frameworks || [];

  return (
    <div className="space-y-8 max-w-7xl mx-auto">
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
            onClick={fetchMetrics}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#F5F7FA] hover:bg-[#EEF1F6] text-[#0E1726] border border-[#E6E9F0] text-xs font-semibold transition"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
          <div className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-semibold">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-ping" />
            System Live
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
                {loading ? "..." : metrics?.totalRequests ?? 0}
              </h3>
            </div>
            <div className="p-2.5 rounded-xl bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
              <Activity className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-4 flex items-center justify-between text-xs">
            <span className="text-[#6B7488]">Total API calls intercepted</span>
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
              <p className="text-[10px] uppercase tracking-widest font-bold text-[#6B7488]">PII Redactions</p>
              <h3 className="text-2xl font-bold text-[#0E1726] mt-2">
                {loading ? "..." : metrics?.redactions24h ?? 0}
              </h3>
            </div>
            <div className="p-2.5 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
              <EyeOff className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-4 flex items-center justify-between text-xs">
            <span className="text-[#6B7488]">Masked or hashed (last 24h)</span>
            <span className="text-emerald-400 font-semibold">Active Engine</span>
          </div>
        </div>

        {/* Requests Per Second Card */}
        <div className="relative overflow-hidden rounded-[20px] bg-white border border-[#E6E9F0] p-6 shadow-xl hover:border-sky-500/30 transition-all duration-300">
          <div className="absolute top-0 right-0 w-24 h-24 rounded-full bg-sky-500/5 blur-[40px] pointer-events-none" />
          <div className="flex justify-between items-start">
            <div>
              <p className="text-[10px] uppercase tracking-widest font-bold text-[#6B7488]">Throughput</p>
              <h3 className="text-2xl font-bold text-[#0E1726] mt-2">
                {loading ? (
                  "..."
                ) : metrics?.requestsPerSec !== null && metrics?.requestsPerSec !== undefined ? (
                  `${metrics.requestsPerSec} req/s`
                ) : (
                  <span className="text-sm font-medium text-[#6B7488]">No data available yet</span>
                )}
              </h3>
            </div>
            <div className="p-2.5 rounded-xl bg-sky-500/10 border border-sky-500/20 text-sky-400">
              <RefreshCw className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-4 flex items-center justify-between text-xs text-[#6B7488]">
            <span>Average request frequency</span>
            <span>Real-time</span>
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
                  <span className="text-sm font-medium text-[#6B7488]">No data available yet</span>
                )}
              </h3>
            </div>
            <div className="p-2.5 rounded-xl bg-purple-500/10 border border-purple-500/20 text-purple-400">
              <Clock className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-4 flex items-center justify-between text-xs text-[#6B7488]">
            <span>99th percentile request overhead</span>
            <span>Proxy latency</span>
          </div>
        </div>

      </div>

      {/* Main Grid: Compliance Readiness + Approvals Quick Look */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* Compliance Readiness Column (Span 2) */}
        <div className="lg:col-span-2 rounded-[20px] bg-white border border-[#E6E9F0] p-6 shadow-xl flex flex-col justify-between">
          <div>
            <h3 className="text-lg font-bold text-[#0E1726] flex items-center gap-2">
              <Award className="w-5 h-5 text-indigo-400" />
              AI Governance Readiness {complianceScores ? `(${complianceScores.overall_score}%)` : ""}
            </h3>
            <p className="text-[#6B7488] text-xs mt-1">
              Live readiness based on evidence records, findings, audit-chain events, policies, and redaction activity.
            </p>
          </div>

          <div className="space-y-6 mt-6">
            {complianceReadiness.length === 0 && (
              <div className="rounded-xl border border-[#E6E9F0] bg-[#F5F7FA] p-4 text-xs text-[#6B7488]">
                Compliance scores will appear after the scoring endpoint responds.
              </div>
            )}
            {complianceReadiness.map((framework) => {
              const meta = frameworkLabels[framework.framework];
              return (
              <div key={framework.framework} className="space-y-2">
                <div className="flex justify-between text-xs">
                  <span className="font-semibold text-[#475069]">{meta.name}</span>
                  <span className="font-bold text-[#0E1726]">{framework.score}% score</span>
                </div>
                <div className="h-2 w-full bg-[#F5F7FA]/80 rounded-full overflow-hidden">
                  <div
                    className={`h-full ${meta.color} rounded-full transition-all duration-1000`}
                    style={{ width: `${framework.score}%` }}
                  />
                </div>
                <p className="text-[10px] text-[#6B7488]">
                  {meta.desc} - {framework.metrics.evidence_count} evidence - {framework.metrics.open_findings} open findings
                </p>
              </div>
            );})}
          </div>

          <div className="mt-6 pt-4 border-t border-[#E6E9F0] flex justify-end">
            <Link href="/compliance" className="text-xs font-semibold text-indigo-400 hover:text-indigo-300 flex items-center gap-1 transition">
              View framework controls <ArrowUpRight className="w-3.5 h-3.5" />
            </Link>
          </div>
        </div>

        {/* Open Approvals Quick Look Card */}
        <div className="rounded-[20px] bg-white/80 border border-[#E6E9F0] p-6 shadow-xl flex flex-col justify-between">
          <div>
            <h3 className="text-lg font-bold text-[#0E1726] flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-emerald-400" />
              Governance Status
            </h3>
            <p className="text-[#6B7488] text-xs mt-1">
              Runtime controls protecting traffic before it reaches the model provider.
            </p>
          </div>

          <div className="my-6 flex flex-col items-center justify-center text-center py-4">
            {loading ? (
              <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-indigo-500" />
            ) : metrics?.openApprovals && metrics.openApprovals > 0 ? (
              <>
                <div className="w-16 h-16 rounded-full bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-2xl font-black text-amber-400 mb-3 animate-pulse">
                  {metrics.openApprovals}
                </div>
                <h4 className="text-sm font-semibold text-[#0E1726]">Pending Authorization</h4>
                <p className="text-[11px] text-[#6B7488] max-w-[200px] mt-1">
                  A governance action is waiting for admin review.
                </p>
              </>
            ) : (
              <>
                <CheckCircle2 className="w-12 h-12 text-emerald-400 mb-3" />
                <h4 className="text-sm font-semibold text-[#0E1726]">All Clear</h4>
                <p className="text-[11px] text-[#6B7488] max-w-[200px] mt-1">
                  No pending governance actions awaiting review.
                </p>
              </>
            )}
          </div>

          <Link
            href="/gateway"
            className="w-full text-center py-2.5 rounded-lg bg-[#F5F7FA] hover:bg-[#F5F7FA] text-xs font-semibold text-[#0E1726] border border-[#E6E9F0] transition"
          >
            Configure Gateway
          </Link>
        </div>

      </div>
    </div>
  );
}
