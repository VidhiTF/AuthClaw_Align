"use client";

import React, { useState, useEffect, useCallback } from "react";
import {
  AlertTriangle,
  RefreshCw,
  Search,
  ChevronLeft,
  ChevronRight,
  X,
  ShieldAlert,
  Filter,
  ExternalLink,
  AlertCircle,
  CheckCircle2,
  TrendingUp,
} from "lucide-react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import FilterSelect from "@/components/filter-select";
import { formatDateTime, formatLabel, severityConfig, shortId, statusConfig } from "@/lib/ui-format";

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

interface Finding {
  id: string;
  tenant_id: string;
  workflow_id: string | null;
  evidence_id: string | null;
  framework: string;
  finding_key: string;
  title: string;
  description: string | null;
  severity: string;
  status: string;
  finding_type: string;
  risk_score: number;
  remediation_summary: string | null;
  owner_user_id: string | null;
  created_at: string;
  updated_at: string;
  resolved_at: string | null;
  evidence_created_at: string | null;
}

interface FindingListResponse {
  total: number;
  page: number;
  page_size: number;
  items: Finding[];
}

interface DashboardSummary {
  open_findings: number;
  critical_findings: number;
  resolved_findings: number;
  average_risk_score: number;
  severity_distribution: Record<string, number>;
}

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

const FRAMEWORK_OPTIONS = ["", "GDPR", "HIPAA", "SOC2", "RED_TEAM"] as const;
const FINDING_TYPE_OPTIONS = [
  "",
  "PII_EXPOSURE",
  "POLICY_VIOLATION",
  "ACCESS_CONTROL",
  "DATA_RETENTION",
  "ENCRYPTION",
  "AUDIT_GAP",
  "AI_GOVERNANCE",
  "PROMPT_INJECTION",
  "DATA_DISCLOSURE",
  "SYCOPHANCY",
  "HARMFUL_CONTENT",
] as const;
const SEVERITY_OPTIONS = ["", "critical", "high", "medium", "low", "info"] as const;
const STATUS_OPTIONS = [
  "",
  "OPEN",
  "ACKNOWLEDGED",
  "IN_PROGRESS",
  "AWAITING_APPROVAL",
  "RESOLVED",
  "FALSE_POSITIVE",
  "ACCEPTED_RISK"
] as const;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------


// -----------------------------------------------------------------------------
// Detail Drawer
// -----------------------------------------------------------------------------

function FindingDrawer({
  finding,
  onClose,
  onStatusChange,
  canManage,
}: {
  finding: Finding;
  onClose: () => void;
  onStatusChange: (findingId: string, newStatus: string) => void;
  canManage: boolean;
}) {
  const sev = severityConfig(finding.severity);
  const st = statusConfig(finding.status);

  return (
    <>
      <div
        className="fixed inset-0 bg-black/50 backdrop-blur-sm z-40"
        onClick={onClose}
      />
      <aside className="fixed right-0 top-0 h-full w-full max-w-xl bg-white border-l border-[#E6E9F0] z-50 flex flex-col shadow-2xl overflow-hidden">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#E6E9F0] bg-white">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-indigo-600/20 border border-indigo-500/30 flex items-center justify-center">
              <AlertTriangle className="w-4 h-4 text-indigo-400" />
            </div>
            <div>
              <p className="text-xs text-[#6B7488] font-medium uppercase tracking-wider">Finding Detail</p>
              <p className="text-sm font-mono text-[#475069]">{shortId(finding.id)}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 text-[#6B7488] hover:text-[#0E1726] hover:bg-[#F5F7FA]/50 rounded-lg transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto custom-scrollbar p-6 space-y-6">
          <div className="flex items-start justify-between gap-4">
            <div>
              <h2 className="text-lg font-semibold text-[#0E1726] tracking-wide">{finding.title}</h2>
              <div className="flex items-center gap-2 mt-2">
                <span className={`px-2.5 py-1 rounded-md text-xs font-semibold border ${sev.bg} ${sev.text} ${sev.border}`}>
                  {finding.severity.toUpperCase()}
                </span>
                <span className={`px-2.5 py-1 rounded-md text-xs font-medium border ${st.bg} ${st.text} ${st.border}`}>
                  {formatLabel(finding.status)}
                </span>
                <span className="px-2.5 py-1 rounded-md text-xs font-medium bg-[#F5F7FA]/50 text-[#475069] border border-[#E6E9F0]/50">
                  {finding.framework}
                </span>
              </div>
            </div>
          </div>

          <div className="space-y-4">
            <h3 className="text-sm font-semibold text-[#0E1726]">Finding Information</h3>
            <div className="bg-white border border-[#E6E9F0] rounded-xl p-4 space-y-3">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-xs text-[#6B7488] mb-1">Finding Type</p>
                  <p className="text-sm text-[#475069] font-medium">{formatLabel(finding.finding_type)}</p>
                </div>
                <div>
                  <p className="text-xs text-[#6B7488] mb-1">Risk Score</p>
                  <p className="text-sm text-[#475069] font-mono">{(finding.risk_score * 100).toFixed(0)}%</p>
                </div>
                <div>
                  <p className="text-xs text-[#6B7488] mb-1">Owner</p>
                  <p className="text-sm text-[#475069]">
                    {finding.owner_user_id ?
                      (finding.owner_user_id.includes('@') ? finding.owner_user_id : shortId(finding.owner_user_id))
                      : "Unassigned"}
                  </p>
                </div>
                <div className="col-span-2">
                  <div className="grid grid-cols-2 gap-4 bg-[#F5F7FA] p-3 rounded-lg border border-[#E6E9F0]">
                    <div>
                      <p className="text-xs text-[#6B7488] mb-1">Evidence Created</p>
                      <p className="text-sm text-[#475069] font-mono">{finding.evidence_created_at ? formatDateTime(finding.evidence_created_at) : "N/A"}</p>
                    </div>
                    <div>
                      <p className="text-xs text-[#6B7488] mb-1">Finding Created</p>
                      <p className="text-sm text-[#475069] font-mono">{formatDateTime(finding.created_at)}</p>
                    </div>
                  </div>
                </div>
                <div className="col-span-2">
                  <p className="text-xs text-[#6B7488] mb-1">Finding Key</p>
                  <p className="text-xs text-[#475069] font-mono break-all bg-[#F5F7FA] p-2 rounded-md border border-[#E6E9F0]">{finding.finding_key}</p>
                </div>
              </div>
              <div>
                <p className="text-xs text-[#6B7488] mb-1">Description</p>
                <p className="text-sm text-[#475069] leading-relaxed bg-[#F5F7FA] p-3 rounded-lg border border-[#E6E9F0]">
                  {finding.description || "No description provided."}
                </p>
              </div>
            </div>
          </div>

          <div className="space-y-4">
            <h3 className="text-sm font-semibold text-[#0E1726]">Traceability</h3>
            <div className="bg-white border border-[#E6E9F0] rounded-xl p-4 space-y-3">
              <div>
                <p className="text-xs text-[#6B7488] mb-1">Workflow Reference</p>
                <div className="flex items-center gap-2">
                  <span className="text-sm text-[#475069] font-mono bg-[#F5F7FA] px-2 py-1 rounded border border-[#E6E9F0]">
                    {finding.workflow_id || "N/A"}
                  </span>
                </div>
              </div>
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-[#6B7488] mb-1">Evidence Reference</p>
                  <div className="flex items-center gap-2">
                    <span className="text-sm text-[#475069] font-mono bg-[#F5F7FA] px-2 py-1 rounded border border-[#E6E9F0]">
                      {finding.evidence_id || "N/A"}
                    </span>
                  </div>
                </div>
                <div className="text-right">
                  <p className="text-xs text-[#6B7488] mb-1">Related Evidence</p>
                  <p className="text-sm text-[#475069] font-medium">{finding.evidence_id ? "1 record" : "0 records"}</p>
                </div>
              </div>
              {finding.evidence_id && (
                <Link
                  href={`/evidence?evidence_id=${finding.evidence_id}&openDrawer=true`}
                  className="flex items-center justify-center gap-2 w-full py-2 bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-400 text-sm font-medium rounded-lg border border-indigo-500/30 transition-colors"
                >
                  <ExternalLink className="w-4 h-4" />
                  View Evidence
                </Link>
              )}
            </div>
          </div>

          {finding.remediation_summary && (
            <div className="space-y-4">
              <h3 className="text-sm font-semibold text-[#0E1726]">Suggested Remediation</h3>
              <div className="bg-white border border-[#E6E9F0] rounded-xl p-4">
                <p className="text-sm text-[#475069] leading-relaxed whitespace-pre-wrap">
                  {finding.remediation_summary}
                </p>
              </div>
            </div>
          )}

          <div className="space-y-4">
            <h3 className="text-sm font-semibold text-[#0E1726]">Next Action</h3>
            <div className="bg-white border border-[#E6E9F0] rounded-xl p-4 space-y-3">
              <Link
                href="/agent"
                className="flex items-center justify-center gap-2 w-full py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-semibold rounded-lg transition-colors"
              >
                <ExternalLink className="w-4 h-4" />
                Open Agent & Remediation
              </Link>
              {finding.framework === "RED_TEAM" && (
                <Link
                  href="/risk"
                  className="flex items-center justify-center gap-2 w-full py-2 bg-white hover:bg-[#F5F7FA] text-[#475069] text-sm font-semibold rounded-lg border border-[#E6E9F0] transition-colors"
                >
                  <ExternalLink className="w-4 h-4" />
                  Review Red-Team Runs
                </Link>
              )}
            </div>
          </div>

          <div className="space-y-4">
            <h3 className="text-sm font-semibold text-[#0E1726]">Manage Status</h3>
            <div className="bg-white border border-[#E6E9F0] rounded-xl p-4 flex flex-col gap-3">
              <label className="text-xs text-[#6B7488]">Update Status</label>
              <select
                value={finding.status}
                onChange={(e) => onStatusChange(finding.id, e.target.value)}
                disabled={!canManage}
                className="bg-[#F5F7FA] border border-[#E6E9F0] text-[#475069] text-sm rounded-lg px-3 py-2 outline-none focus:border-indigo-500/50"
              >
                {STATUS_OPTIONS.slice(1).map(s => (
                  <option key={s} value={s}>{formatLabel(s)}</option>
                ))}
              </select>
            </div>
          </div>

        </div>
      </aside>
    </>
  );
}

// -----------------------------------------------------------------------------
// Main Dashboard
// -----------------------------------------------------------------------------

export default function FindingsDashboard() {
  const searchParams = useSearchParams();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [canManage, setCanManage] = useState(false);

  const [summary, setSummary] = useState<DashboardSummary | null>(null);

  const [page, setPage] = useState(1);
  const [pageSize] = useState(20);

  const [framework, setFramework] = useState(searchParams.get("framework") || "");
  const [findingType, setFindingType] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");

  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  useEffect(() => {
    fetch("/api/auth/session")
      .then((response) => response.json())
      .then((session) => setCanManage(["owner", "admin"].includes(String(session.role || "").toLowerCase())))
      .catch(() => setCanManage(false));
  }, []);

  const fetchSummary = useCallback(async () => {
    try {
      const res = await fetch("/api/findings/summary/dashboard");
      if (!res.ok) throw new Error("Failed to fetch dashboard summary");
      const data = await res.json();
      setSummary(data);
    } catch (e: unknown) {
      console.error(e);
    }
  }, []);

  const fetchFindings = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams({
        page: page.toString(),
        page_size: pageSize.toString(),
      });
      if (framework) params.append("framework", framework);
      if (findingType) params.append("finding_type", findingType);
      if (severity) params.append("severity", severity);
      if (status) params.append("status", status);

      const res = await fetch(`/api/findings?${params.toString()}`);
      if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`);
      const data: FindingListResponse = await res.json();
      setFindings(data.items);
      setTotal(data.total);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to load findings");
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, framework, findingType, severity, status]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void fetchFindings();
      void fetchSummary();
    }, 0);
    return () => window.clearTimeout(timer);
  }, [fetchFindings, fetchSummary]);

  useEffect(() => {
    const findingId = searchParams.get("finding_id");
    if (!findingId || selectedFinding?.id === findingId) return;
    const timer = window.setTimeout(() => {
      fetch(`/api/findings/${findingId}`)
        .then((res) => res.json())
        .then((data) => {
          if (data?.id) setSelectedFinding(data);
        })
        .catch((err) => console.error("Failed to load finding drawer", err));
    }, 0);
    return () => window.clearTimeout(timer);
  }, [searchParams, selectedFinding]);

  const handleStatusChange = async (findingId: string, newStatus: string) => {
    try {
      const res = await fetch(`/api/findings/${findingId}/status`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: newStatus }),
      });
      if (!res.ok) throw new Error("Failed to update status");
      const updated = await res.json();
      setFindings((prev) => prev.map((f) => (f.id === findingId ? updated : f)));
      if (selectedFinding?.id === findingId) {
        setSelectedFinding(updated);
      }
      fetchSummary();
    } catch (e: unknown) {
      console.error(e);
    }
  };

  const totalPages = Math.ceil(total / pageSize);

  return (
    <div className="p-6 md:p-8 max-w-[1600px] mx-auto space-y-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl md:text-3xl font-bold text-[#0E1726] tracking-tight flex items-center gap-3">
            <AlertTriangle className="w-8 h-8 text-indigo-400" />
            Findings Dashboard
          </h1>
          <p className="text-[#6B7488] mt-2 text-sm max-w-2xl">
            Operational compliance layer. Review and remediate actionable compliance issues derived from evidence.
          </p>
        </div>
        <button
          onClick={fetchFindings}
          className="flex items-center justify-center gap-2 px-4 py-2 bg-white border border-[#E6E9F0] hover:border-[#A78BFA] rounded-lg text-sm text-[#475069] transition-colors shadow-sm self-start md:self-auto"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin text-indigo-400" : ""}`} />
          Refresh
        </button>
      </div>

      {/* Summary Cards */}
      {summary && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-white border border-[#E6E9F0] rounded-xl p-5 shadow-lg relative overflow-hidden">
             <div className="absolute top-0 right-0 p-4 opacity-10">
               <AlertTriangle className="w-16 h-16" />
             </div>
             <p className="text-sm text-[#6B7488] font-medium">Critical Findings</p>
             <p className="text-3xl font-bold text-red-400 mt-2">{summary.critical_findings}</p>
          </div>
          <div className="bg-white border border-[#E6E9F0] rounded-xl p-5 shadow-lg relative overflow-hidden">
             <div className="absolute top-0 right-0 p-4 opacity-10">
               <ShieldAlert className="w-16 h-16" />
             </div>
             <p className="text-sm text-[#6B7488] font-medium">Open Findings</p>
             <p className="text-3xl font-bold text-indigo-400 mt-2">{summary.open_findings}</p>
          </div>
          <div className="bg-white border border-[#E6E9F0] rounded-xl p-5 shadow-lg relative overflow-hidden">
             <div className="absolute top-0 right-0 p-4 opacity-10">
               <CheckCircle2 className="w-16 h-16" />
             </div>
             <p className="text-sm text-[#6B7488] font-medium">Resolved Findings</p>
             <p className="text-3xl font-bold text-emerald-400 mt-2">{summary.resolved_findings}</p>
          </div>
          <div className="bg-white border border-[#E6E9F0] rounded-xl p-5 shadow-lg relative overflow-hidden">
             <div className="absolute top-0 right-0 p-4 opacity-10">
               <TrendingUp className="w-16 h-16" />
             </div>
             <p className="text-sm text-[#6B7488] font-medium">Average Risk</p>
             <p className="text-3xl font-bold text-yellow-400 mt-2">{(summary.average_risk_score * 100).toFixed(0)}%</p>
          </div>
        </div>
      )}

      {/* Severity Distribution Cards */}
      {summary?.severity_distribution && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-white border border-red-500/30 rounded-xl p-4 shadow-sm flex items-center justify-between">
             <p className="text-sm text-red-400 font-medium">Critical</p>
             <p className="text-xl font-bold text-[#0E1726]">{summary.severity_distribution.critical || 0}</p>
          </div>
          <div className="bg-white border border-orange-500/30 rounded-xl p-4 shadow-sm flex items-center justify-between">
             <p className="text-sm text-orange-400 font-medium">High</p>
             <p className="text-xl font-bold text-[#0E1726]">{summary.severity_distribution.high || 0}</p>
          </div>
          <div className="bg-white border border-yellow-500/30 rounded-xl p-4 shadow-sm flex items-center justify-between">
             <p className="text-sm text-yellow-400 font-medium">Medium</p>
             <p className="text-xl font-bold text-[#0E1726]">{summary.severity_distribution.medium || 0}</p>
          </div>
          <div className="bg-white border border-blue-500/30 rounded-xl p-4 shadow-sm flex items-center justify-between">
             <p className="text-sm text-blue-400 font-medium">Low</p>
             <p className="text-xl font-bold text-[#0E1726]">{summary.severity_distribution.low || 0}</p>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="bg-white border border-[#E6E9F0] rounded-xl p-4 flex flex-wrap gap-4 items-center shadow-sm">
        <div className="flex items-center gap-2 text-[#6B7488] mr-2">
          <Filter className="w-4 h-4" />
          <span className="text-sm font-medium">Filters:</span>
        </div>
        <FilterSelect label="All Frameworks" value={framework} options={FRAMEWORK_OPTIONS} onChange={(v) => { setFramework(v); setPage(1); }} />
        <FilterSelect label="All Types" value={findingType} options={FINDING_TYPE_OPTIONS} onChange={(v) => { setFindingType(v); setPage(1); }} />
        <FilterSelect label="All Severities" value={severity} options={SEVERITY_OPTIONS} onChange={(v) => { setSeverity(v); setPage(1); }} />
        <FilterSelect label="All Statuses" value={status} options={STATUS_OPTIONS} onChange={(v) => { setStatus(v); setPage(1); }} />

        {(framework || findingType || severity || status) && (
          <button
            onClick={() => {
              setFramework("");
              setFindingType("");
              setSeverity("");
              setStatus("");
              setPage(1);
            }}
            className="text-xs text-[#6B7488] hover:text-[#475069] underline underline-offset-2 ml-auto"
          >
            Clear Filters
          </button>
        )}
      </div>

      {/* Table */}
      <div className="bg-white border border-[#E6E9F0] rounded-xl shadow-xl overflow-hidden flex flex-col min-h-[400px]">
        {error ? (
          <div className="flex-1 flex flex-col items-center justify-center p-8 text-center">
            <AlertCircle className="w-10 h-10 text-red-500/50 mb-4" />
            <p className="text-red-400 font-medium">Failed to load findings</p>
            <p className="text-[#6B7488] text-sm mt-1">{error}</p>
          </div>
        ) : loading && findings.length === 0 ? (
          <div className="flex-1 flex flex-col items-center justify-center p-8">
            <RefreshCw className="w-8 h-8 text-indigo-500/50 animate-spin mb-4" />
            <p className="text-[#6B7488] text-sm font-medium animate-pulse">Loading findings...</p>
          </div>
        ) : findings.length === 0 ? (
          <div className="flex-1 flex flex-col items-center justify-center p-12 text-center">
            <div className="w-16 h-16 rounded-full bg-[#F5F7FA]/50 flex items-center justify-center mb-4 border border-[#E6E9F0]/50">
              <Search className="w-8 h-8 text-[#6B7488]" />
            </div>
            <p className="text-[#475069] font-medium text-lg">No findings found</p>
            <p className="text-[#6B7488] text-sm mt-2 max-w-sm">
              Adjust your filters or trigger a compliance workflow to generate findings.
            </p>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-[#E6E9F0] bg-white">
                    <th className="py-4 px-6 text-xs font-semibold text-[#6B7488] uppercase tracking-wider">Severity</th>
                    <th className="py-4 px-6 text-xs font-semibold text-[#6B7488] uppercase tracking-wider">Title</th>
                    <th className="py-4 px-6 text-xs font-semibold text-[#6B7488] uppercase tracking-wider">Framework</th>
                    <th className="py-4 px-6 text-xs font-semibold text-[#6B7488] uppercase tracking-wider">Status</th>
                    <th className="py-4 px-6 text-xs font-semibold text-[#6B7488] uppercase tracking-wider">Owner</th>
                    <th className="py-4 px-6 text-xs font-semibold text-[#6B7488] uppercase tracking-wider">Created</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#E6E9F0]/60">
                  {findings.map((f) => {
                    const sev = severityConfig(f.severity);
                    const st = statusConfig(f.status);

                    return (
                      <tr
                        key={f.id}
                        onClick={() => setSelectedFinding(f)}
                        className="hover:bg-[#F5F7FA]/30 transition-colors cursor-pointer group"
                      >
                        <td className="py-4 px-6">
                          <div className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold border ${sev.bg} ${sev.text} ${sev.border}`}>
                            <div className={`w-1.5 h-1.5 rounded-full ${sev.dot}`} />
                            {f.severity.toUpperCase()}
                          </div>
                        </td>
                        <td className="py-4 px-6">
                          <p className="text-sm text-[#0E1726] font-medium group-hover:text-indigo-300 transition-colors line-clamp-1">
                            {f.title}
                          </p>
                        </td>
                        <td className="py-4 px-6">
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-[#F5F7FA] text-[#475069] border border-[#E6E9F0]">
                            {f.framework}
                          </span>
                        </td>
                        <td className="py-4 px-6">
                          <span className={`inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium border ${st.bg} ${st.text} ${st.border}`}>
                            {formatLabel(f.status)}
                          </span>
                        </td>
                        <td className="py-4 px-6 text-sm text-[#6B7488]">
                          {f.owner_user_id ? shortId(f.owner_user_id) : "Unassigned"}
                        </td>
                        <td className="py-4 px-6 text-sm text-[#6B7488] font-mono">
                          {formatDateTime(f.created_at)}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            <div className="mt-auto px-6 py-4 border-t border-[#E6E9F0] bg-white flex items-center justify-between">
              <p className="text-sm text-[#6B7488]">
                Showing <span className="font-medium text-[#475069]">{findings.length}</span> of <span className="font-medium text-[#475069]">{total}</span>
              </p>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page === 1}
                  className="p-1.5 rounded-lg border border-[#E6E9F0] text-[#6B7488] hover:text-[#0E1726] hover:bg-[#F5F7FA] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  <ChevronLeft className="w-4 h-4" />
                </button>
                <span className="text-sm text-[#6B7488] font-medium min-w-[3rem] text-center">
                  {page} / {totalPages || 1}
                </span>
                <button
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  disabled={page >= totalPages}
                  className="p-1.5 rounded-lg border border-[#E6E9F0] text-[#6B7488] hover:text-[#0E1726] hover:bg-[#F5F7FA] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          </>
        )}
      </div>

      {selectedFinding && (
        <FindingDrawer
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
          onStatusChange={handleStatusChange}
          canManage={canManage}
        />
      )}
    </div>
  );
}
