"use client";

import React, { useState, useEffect, useCallback } from "react";
import {
  DatabaseZap,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  X,
  FileSearch,
  ShieldAlert,
  FileCheck,
  FileWarning,
  Link2,
  Clock,
  Filter,
  AlertCircle,
  CheckCircle2,
  Info,
} from "lucide-react";
import { useSearchParams, useRouter } from "next/navigation";
import FilterSelect from "@/components/filter-select";
import { formatDateTime, formatLabel, severityConfig, shortId } from "@/lib/ui-format";

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

interface EvidenceLink {
  id: string;
  linked_type: string;
  linked_id: string;
  created_at: string;
}

interface EvidenceRecord {
  id: string;
  tenant_id: string;
  workflow_id: string | null;
  framework: string;
  source_type: string;
  source_reference: string | null;
  evidence_type: string;
  evidence_data: Record<string, unknown>;
  severity: string;
  created_at: string;
  links: EvidenceLink[];
}

interface EvidenceListResponse {
  total: number;
  page: number;
  page_size: number;
  items: EvidenceRecord[];
}

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

const FRAMEWORK_OPTIONS = ["", "GDPR", "HIPAA", "SOC2"] as const;
const EVIDENCE_TYPE_OPTIONS = [
  "",
  "pii_detected",
  "policy_violation",
  "approval_record",
  "audit_log",
  "scan_result",
] as const;
const SEVERITY_OPTIONS = ["", "critical", "high", "medium", "low", "info"] as const;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

function evidenceTypeIcon(evidenceType: string) {
  switch (evidenceType) {
    case "pii_detected":
      return <ShieldAlert className="w-4 h-4 text-red-400" />;
    case "policy_violation":
      return <FileWarning className="w-4 h-4 text-orange-400" />;
    case "approval_record":
      return <FileCheck className="w-4 h-4 text-emerald-400" />;
    case "audit_log":
      return <FileSearch className="w-4 h-4 text-blue-400" />;
    case "scan_result":
      return <CheckCircle2 className="w-4 h-4 text-teal-400" />;
    default:
      return <Info className="w-4 h-4 text-[#6B7488]" />;
  }
}

function formatEvidenceType(t: string) {
  return formatLabel(t);
}


// -----------------------------------------------------------------------------
// Detail Drawer
// -----------------------------------------------------------------------------

function EvidenceDrawer({
  record,
  onClose,
}: {
  record: EvidenceRecord;
  onClose: () => void;
}) {
  const sev = severityConfig(record.severity);

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/50 backdrop-blur-sm z-40"
        onClick={onClose}
      />

      {/* Drawer panel */}
      <aside className="fixed right-0 top-0 h-full w-full max-w-xl bg-white border-l border-[#E6E9F0] z-50 flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#E6E9F0] bg-white">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-indigo-600/20 border border-indigo-500/30 flex items-center justify-center">
              <DatabaseZap className="w-4 h-4 text-indigo-400" />
            </div>
            <div>
              <p className="text-xs text-[#6B7488] font-medium uppercase tracking-wider">Evidence Detail</p>
              <p className="text-sm font-mono text-[#475069]">{shortId(record.id)}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-[#6B7488] hover:text-[#0E1726] hover:bg-[#F5F7FA]/60 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Scrollable body */}
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-6">

          {/* Severity + type badges */}
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold border ${sev.bg} ${sev.text} ${sev.border}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${sev.dot}`} />
              {record.severity.charAt(0).toUpperCase() + record.severity.slice(1)}
            </span>
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold border bg-indigo-500/10 text-indigo-400 border-indigo-500/20">
              {evidenceTypeIcon(record.evidence_type)}
              {formatEvidenceType(record.evidence_type)}
            </span>
            <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-semibold border bg-violet-500/10 text-violet-400 border-violet-500/20">
              {record.framework}
            </span>
          </div>

          {/* Metadata grid */}
          <div className="grid grid-cols-2 gap-3">
            {[
              { label: "Evidence ID", value: record.id, mono: true },
              { label: "Source Type", value: record.source_type.replace(/_/g, " ") },
              { label: "Created", value: formatDateTime(record.created_at) },
              { label: "Framework", value: record.framework },
            ].map(({ label, value, mono }) => (
              <div key={label} className="bg-white rounded-lg p-3 border border-[#E6E9F0]">
                <p className="text-[10px] uppercase tracking-wider font-semibold text-[#6B7488] mb-1">{label}</p>
                <p className={`text-xs text-[#0E1726] break-all ${mono ? "font-mono" : ""}`}>{value}</p>
              </div>
            ))}
          </div>

          {/* Source reference */}
          {record.source_reference && (
            <div className="bg-white rounded-lg p-3 border border-[#E6E9F0]">
              <p className="text-[10px] uppercase tracking-wider font-semibold text-[#6B7488] mb-1">Source Reference</p>
              <p className="text-xs font-mono text-indigo-300 break-all">{record.source_reference}</p>
            </div>
          )}

          {/* Workflow reference */}
          {record.workflow_id && (
            <div className="bg-white rounded-lg p-3 border border-[#E6E9F0]">
              <p className="text-[10px] uppercase tracking-wider font-semibold text-[#6B7488] mb-1">Workflow Reference</p>
              <p className="text-xs font-mono text-teal-300 break-all">{record.workflow_id}</p>
            </div>
          )}

          {/* Evidence Data */}
          <div>
            <p className="text-[10px] uppercase tracking-wider font-semibold text-[#6B7488] mb-2">Evidence Payload</p>
            <div className="bg-[#F5F7FA] rounded-lg border border-[#E6E9F0] p-4 overflow-auto max-h-56">
              <pre className="text-xs font-mono text-[#475069] whitespace-pre-wrap leading-relaxed">
                {JSON.stringify(record.evidence_data, null, 2)}
              </pre>
            </div>
          </div>

          {/* Traceability Links */}
          {record.links && record.links.length > 0 && (
            <div>
              <p className="text-[10px] uppercase tracking-wider font-semibold text-[#6B7488] mb-2 flex items-center gap-1.5">
                <Link2 className="w-3 h-3" />
                Traceability Links ({record.links.length})
              </p>
              <div className="space-y-2">
                {record.links.map((link) => (
                  <div
                    key={link.id}
                    className="flex items-center justify-between bg-white rounded-lg px-3 py-2.5 border border-[#E6E9F0]"
                  >
                    <div>
                      <span className="inline-block px-1.5 py-0.5 rounded text-[10px] font-semibold bg-[#EEF1F6]/50 text-[#6B7488] uppercase mr-2">
                        {link.linked_type}
                      </span>
                      <span className="text-xs font-mono text-[#475069]">{link.linked_id}</span>
                    </div>
                    <span className="text-[10px] text-[#6B7488]">{formatDateTime(link.created_at)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </aside>
    </>
  );
}

// -----------------------------------------------------------------------------
// Main page
// -----------------------------------------------------------------------------

export default function EvidencePage() {
  const searchParams = useSearchParams();
  const router = useRouter();

  const [items, setItems] = useState<EvidenceRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [framework, setFramework] = useState(searchParams.get("framework") || "");
  const [evidenceType, setEvidenceType] = useState(searchParams.get("evidence_type") || "");
  const [severity, setSeverity] = useState(searchParams.get("severity") || "");
  const [page, setPage] = useState(1);
  const pageSize = 20;

  // Detail drawer
  const [selectedRecord, setSelectedRecord] = useState<EvidenceRecord | null>(null);

  const fetchEvidence = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      params.set("page", String(page));
      params.set("page_size", String(pageSize));
      if (framework) params.set("framework", framework);
      if (evidenceType) params.set("evidence_type", evidenceType);
      if (severity) params.set("severity", severity);

      const res = await fetch(`/api/evidence?${params.toString()}`);
      if (res.status === 401) {
        window.location.href = "/login";
        return;
      }
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || `HTTP ${res.status}`);
      }
      const data: EvidenceListResponse = await res.json();
      setItems(data.items || []);
      setTotal(data.total || 0);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to load evidence";
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, [framework, evidenceType, severity, page]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void fetchEvidence();
    }, 0);
    return () => window.clearTimeout(timer);
  }, [fetchEvidence]);

  useEffect(() => {
    const evidenceId = searchParams.get("evidence_id");
    const openDrawer = searchParams.get("openDrawer");

    if (evidenceId && openDrawer === "true" && !selectedRecord) {
      // Fetch specifically this record to show it immediately
      fetch(`/api/proxy?path=/v1/evidence/${evidenceId}`)
        .then(res => res.json())
        .then(data => {
          if (data && data.id) setSelectedRecord(data);
        })
        .catch(err => console.error("Failed to load evidence drawer", err));
    }
  }, [searchParams, selectedRecord]);

  const totalPages = Math.ceil(total / pageSize);
  const hasFilters = !!(framework || evidenceType || severity);

  return (
    <div className="min-h-full text-[#0E1726]">
      {/* Page header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-1">
          <div className="w-10 h-10 rounded-xl bg-indigo-600/20 border border-indigo-500/30 flex items-center justify-center shadow-lg shadow-indigo-500/10">
            <DatabaseZap className="w-5 h-5 text-indigo-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-[#0E1726] tracking-tight">Evidence Repository</h1>
            <p className="text-sm text-[#6B7488]">
              Permanent compliance memory - every scan, approval and policy even
            </p>
          </div>
        </div>
      </div>

      {/* Stats bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
        {[
          { label: "Total Records", value: loading ? "-" : total.toLocaleString(), color: "text-[#0E1726]" },
          { label: "Showing", value: loading ? "-" : items.length.toString(), color: "text-[#475069]" },
          { label: "Page", value: loading ? "-" : `${page} / ${totalPages || 1}`, color: "text-[#475069]" },
          { label: "Filter Active", value: hasFilters ? "Yes" : "No", color: hasFilters ? "text-indigo-400" : "text-[#6B7488]" },
        ].map(({ label, value, color }) => (
          <div key={label} className="bg-white rounded-xl border border-[#E6E9F0] px-4 py-3">
            <p className="text-[10px] uppercase tracking-wider font-semibold text-[#6B7488]">{label}</p>
            <p className={`text-xl font-bold mt-1 ${color}`}>{value}</p>
          </div>
        ))}
      </div>

      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-3 mb-5">
        <div className="flex items-center gap-1.5 text-xs text-[#6B7488] font-medium">
          <Filter className="w-3.5 h-3.5" />
          Filters:
        </div>

        <FilterSelec
          label="All Frameworks"
          value={framework}
          options={FRAMEWORK_OPTIONS}
          onChange={(value) => {
            setFramework(value);
            setPage(1);
          }}
        />
        <FilterSelec
          label="All Types"
          value={evidenceType}
          options={EVIDENCE_TYPE_OPTIONS}
          onChange={(value) => {
            setEvidenceType(value);
            setPage(1);
          }}
        />
        <FilterSelec
          label="All Severities"
          value={severity}
          options={SEVERITY_OPTIONS}
          onChange={(value) => {
            setSeverity(value);
            setPage(1);
          }}
        />

        {hasFilters && (
          <button
            onClick={() => {
              setFramework("");
              setEvidenceType("");
              setSeverity("");
              setPage(1);
            }}
            className="flex items-center gap-1 px-3 py-2 rounded-lg text-xs text-red-400 hover:bg-red-500/10 border border-red-500/20 transition-colors"
          >
            <X className="w-3 h-3" />
            Clear
          </button>
        )}

        <button
          onClick={fetchEvidence}
          disabled={loading}
          className="ml-auto flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-400 border border-indigo-500/20 transition-colors disabled:opacity-40"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {/* Error state */}
      {error && (
        <div className="flex items-start gap-3 bg-red-500/10 border border-red-500/20 rounded-xl px-4 py-3 mb-5">
          <AlertCircle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-sm font-medium text-red-400">Failed to load evidence</p>
            <p className="text-xs text-red-400/70 mt-0.5">{error}</p>
          </div>
        </div>
      )}

      {/* Table */}
      <div className="bg-white rounded-xl border border-[#E6E9F0] overflow-hidden">
        {/* Table header */}
        <div className="grid grid-cols-[1fr_90px_130px_110px_90px_120px] gap-4 px-5 py-3 bg-white border-b border-[#E6E9F0]">
          {["Evidence ID", "Framework", "Source Type", "Evidence Type", "Severity", "Timestamp"].map((h) => (
            <span key={h} className="text-[10px] uppercase tracking-wider font-semibold text-[#6B7488]">
              {h}
            </span>
          ))}
        </div>

        {/* Loading skeleton */}
        {loading && (
          <div className="divide-y divide-[#E6E9F0]/40">
            {Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className="grid grid-cols-[1fr_90px_130px_110px_90px_120px] gap-4 px-5 py-3.5 animate-pulse">
                {Array.from({ length: 6 }).map((__, j) => (
                  <div key={j} className="h-3 bg-[#F5F7FA]/60 rounded" />
                ))}
              </div>
            ))}
          </div>
        )}

        {/* Empty state */}
        {!loading && items.length === 0 && (
          <div className="flex flex-col items-center justify-center py-20 text-center">
            <div className="w-16 h-16 rounded-[20px] bg-[#F5F7FA]/40 border border-[#E6E9F0]/40 flex items-center justify-center mb-4">
              <DatabaseZap className="w-8 h-8 text-[#6B7488]" />
            </div>
            <p className="text-base font-semibold text-[#6B7488]">No evidence records found</p>
            <p className="text-sm text-[#6B7488] mt-1 max-w-xs">
              {hasFilters
                ? "Try clearing your filters or run a compliance scan to generate evidence."
                : "Run a GDPR, HIPAA, or SOC2 compliance workflow to populate the repository."}
            </p>
            {hasFilters && (
              <button
                onClick={() => {
                  setFramework("");
                  setEvidenceType("");
                  setSeverity("");
                  setPage(1);
                }}
                className="mt-4 px-4 py-2 rounded-lg text-xs font-medium text-indigo-400 bg-indigo-600/10 border border-indigo-500/20 hover:bg-indigo-600/20 transition-colors"
              >
                Clear filters
              </button>
            )}
          </div>
        )}

        {/* Rows */}
        {!loading && items.length > 0 && (
          <div className="divide-y divide-[#E6E9F0]/30">
            {items.map((record) => {
              const sev = severityConfig(record.severity);
              return (
                <button
                  key={record.id}
                  onClick={() => setSelectedRecord(record)}
                  className="w-full grid grid-cols-[1fr_90px_130px_110px_90px_120px] gap-4 px-5 py-3.5 text-left hover:bg-[#F5F7FA]/20 transition-colors group"
                >
                  {/* Evidence ID */}
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="flex-shrink-0">{evidenceTypeIcon(record.evidence_type)}</span>
                    <span className="font-mono text-xs text-[#475069] truncate group-hover:text-indigo-300 transition-colors">
                      {shortId(record.id)}
                    </span>
                  </div>

                  {/* Framework */}
                  <span className="text-xs font-semibold text-violet-400">{record.framework}</span>

                  {/* Source Type */}
                  <span className="text-xs text-[#6B7488] truncate">
                    {record.source_type.replace(/_/g, " ")}
                  </span>

                  {/* Evidence Type */}
                  <span className="text-xs text-[#475069]">
                    {formatEvidenceType(record.evidence_type)}
                  </span>

                  {/* Severity badge */}
                  <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold border w-fit ${sev.bg} ${sev.text} ${sev.border}`}>
                    <span className={`w-1 h-1 rounded-full ${sev.dot}`} />
                    {record.severity}
                  </span>

                  {/* Timestamp */}
                  <span className="text-[10px] text-[#6B7488] flex items-center gap-1">
                    <Clock className="w-3 h-3 flex-shrink-0" />
                    {new Date(record.created_at).toLocaleDateString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}
                  </span>
                </button>
              );
            })}
          </div>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between mt-5">
          <p className="text-xs text-[#6B7488]">
            Showing {(page - 1) * pageSize + 1}-{Math.min(page * pageSize, total)} of {total} records
          </p>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs text-[#6B7488] hover:text-[#0E1726] bg-[#F5F7FA]/40 hover:bg-[#F5F7FA]/70 border border-[#E6E9F0]/40 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
            >
              <ChevronLeft className="w-3.5 h-3.5" />
              Prev
            </button>
            <span className="px-3 py-1.5 rounded-lg text-xs text-[#475069] bg-indigo-600/20 border border-indigo-500/20 font-medium">
              {page} / {totalPages}
            </span>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
              className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs text-[#6B7488] hover:text-[#0E1726] bg-[#F5F7FA]/40 hover:bg-[#F5F7FA]/70 border border-[#E6E9F0]/40 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
            >
              Nex
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      )}

      {/* Detail Drawer */}
      {selectedRecord && (
        <EvidenceDrawer
          record={selectedRecord}
          onClose={() => {
            setSelectedRecord(null);
            if (searchParams.get("openDrawer") === "true") {
              router.replace("/evidence");
            }
          }}
        />
      )}
    </div>
  );
}
