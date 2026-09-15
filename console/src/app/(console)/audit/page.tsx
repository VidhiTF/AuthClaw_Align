"use client";

import React, { useCallback, useEffect, useRef, useState } from "react";
import {
  ScrollText,
  Search,
  Download,
  CheckCircle2,
  XCircle,
  ChevronLeft,
  ChevronRight,
  RefreshCw,
  SlidersHorizontal,
  AlertTriangle,
  FileDown,
  X,
  Copy,
  Check,
  ShieldCheck,
  ShieldAlert
} from "lucide-react";
import { flashCopy } from "@/lib/clipboard";
import { getErrorMessage } from "@/lib/errors";
import { csvCell, formatDateTime } from "@/lib/ui-format";

interface AuditRecord {
  record_id: string;
  timestamp: string;
  actor_id: string;
  actor_type: string;
  action: string;
  provider?: string;
  model?: string;
  reason?: string;
  response_status?: number;
  duration_ms?: number;
  frameworks_affected?: string[];
  chain_valid?: boolean;
  request_id?: string;
  prior_hash?: string;
  integrity_hash?: string;
  execution_trace?: string | string[] | null;
}

interface AuditExportVerifyResult {
  verified: boolean;
  signature_valid: boolean;
  digest_valid: boolean;
  chain_valid: boolean;
  record_count: number;
  tenant_id: string;
  key_id: string;
  errors: string[];
  first_record_id: string;
  last_record_id: string;
  first_hash: string;
  last_hash: string;
}

const parseExecutionTrace = (trace: unknown): string[] => {
  if (!trace) return [];
  if (Array.isArray(trace)) return trace.map((item) => String(item));
  if (typeof trace === "string") {
    try {
      const parsed = JSON.parse(trace);
      return Array.isArray(parsed) ? parsed.map((item) => String(item)) : [trace];
    } catch {
      return [trace];
    }
  }
  return [String(trace)];
};

const traceValue = (trace: string[], key: string) => {
  const prefix = `${key}=`;
  const item = trace.find((entry) => entry.startsWith(prefix));
  return item ? item.slice(prefix.length) : "";
};

const formatAuditValue = (value: unknown): string => {
  if (value === null || value === undefined) return "";
  if (typeof value === "object") return JSON.stringify(value) || "";
  return String(value);
};

export default function AuditPage() {
  const [records, setRecords] = useState<AuditRecord[]>([]);
  const [auditSource, setAuditSource] = useState("");
  const [integrityCheckedByBackend, setIntegrityCheckedByBackend] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Inspector Panel State
  const [selectedRecord, setSelectedRecord] = useState<AuditRecord | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [signedExportBusy, setSignedExportBusy] = useState(false);
  const [exportStatus, setExportStatus] = useState<string | null>(null);
  const [verifyResult, setVerifyResult] = useState<AuditExportVerifyResult | null>(null);
  const [verifyBusy, setVerifyBusy] = useState(false);
  const verifyInputRef = useRef<HTMLInputElement | null>(null);
  const inspectedProvider: string = typeof selectedRecord?.provider === "string" ? selectedRecord.provider : "";
  const inspectedAction: string = typeof selectedRecord?.action === "string" ? selectedRecord.action : "";
  const inspectedActorId: string = typeof selectedRecord?.actor_id === "string" && selectedRecord.actor_id ? selectedRecord.actor_id : "System";
  const inspectedActorType: string = typeof selectedRecord?.actor_type === "string" && selectedRecord.actor_type ? selectedRecord.actor_type : "N/A";
  const inspectedRequestId: string = typeof selectedRecord?.request_id === "string" && selectedRecord.request_id ? selectedRecord.request_id : "N/A";

  const handleCopy = async (text: string, field: string) => {
    await flashCopy(text, setCopiedField, field, null, 2000);
  };

  // Filters
  const [actionFilter, setActionFilter] = useState("");
  const [actorFilter, setActorFilter] = useState("");
  const [dateStart, setDateStart] = useState("");
  const [dateEnd, setDateEnd] = useState("");
  const [integrityCheck, setIntegrityCheck] = useState(true);

  // Pagination
  const limit = 10;
  const [offset, setOffset] = useState(0);

  const fetchLogs = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const queryParams = new URLSearchParams({
        limit: String(limit),
        offset: String(offset),
        integrity_check: String(integrityCheck),
      });

      if (actionFilter) queryParams.set("action", actionFilter);
      // Wait, actorFilter and date filters can be filtered client-side or we can forward if backend supported,
      // let's do a combination: forward action and filter actor/dates client-side since FastAPI /v1/audit-logs only has action filter natively.
      const res = await fetch(`/api/audit?${queryParams.toString()}`);
      if (res.status === 401) {
        window.location.href = "/login";
        return;
      }
      if (!res.ok) throw new Error("Failed to fetch audit logs");
      const data = await res.json();

      setRecords(data.records || []);
      setAuditSource(data.source || "");
      setIntegrityCheckedByBackend(Boolean(data.integrity_checked));
    } catch (err: unknown) {
      console.warn("Audit fetchLogs failed:", getErrorMessage(err, "Unknown error"));
      setError(getErrorMessage(err, "Could not retrieve audit logs from ClickHouse/Postgres"));
    } finally {
      setLoading(false);
    }
  }, [actionFilter, integrityCheck, limit, offset]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void fetchLogs();
    }, 0);
    return () => window.clearTimeout(timer);
  }, [fetchLogs]);

  // Client-side additional filtering for Actor ID & Date Range
  const filteredRecords = records.filter((rec) => {
    if (actorFilter && !rec.actor_id.toLowerCase().includes(actorFilter.toLowerCase())) {
      return false;
    }
    if (dateStart) {
      const start = new Date(dateStart).getTime();
      const timestamp = new Date(rec.timestamp).getTime();
      if (timestamp < start) return false;
    }
    if (dateEnd) {
      const end = new Date(dateEnd).getTime() + 86400000; // include full day
      const timestamp = new Date(rec.timestamp).getTime();
      if (timestamp > end) return false;
    }
    return true;
  });

  const exportJSON = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(filteredRecords, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `authclaw_audit_export_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const exportCSV = () => {
    const headers = ["Timestamp", "Record ID", "Actor ID", "Action", "Provider", "Model", "Response Status", "Duration (ms)", "Frameworks", "Integrity Status"];
    const rows = filteredRecords.map((r) => [
      r.timestamp,
      r.record_id,
      r.actor_id,
      r.action,
      r.provider,
      r.model,
      r.response_status,
      r.duration_ms,
      r.frameworks_affected ? r.frameworks_affected.join(";") : "",
      r.chain_valid ? "Verified" : "Unverified"
    ]);

    const csvContent = [headers.map(csvCell).join(","), ...rows.map((e) => e.map(csvCell).join(","))].join("\r\n");
    const dataStr = "data:text/csv;charset=utf-8," + encodeURIComponent(csvContent);
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `authclaw_audit_export_${Date.now()}.csv`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const exportSignedAudit = async () => {
    setSignedExportBusy(true);
    setExportStatus(null);
    setVerifyResult(null);
    try {
      const body = {
        action: actionFilter || null,
        start: dateStart ? new Date(dateStart).toISOString() : null,
        end: dateEnd ? new Date(`${dateEnd}T23:59:59.999`).toISOString() : null,
      };
      const res = await fetch("/api/audit/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const artifact = await res.json();
      if (!res.ok) throw new Error(artifact.error || "Signed export failed");
      const dataStr = "data:application/json;charset=utf-8," + encodeURIComponent(JSON.stringify(artifact, null, 2));
      const downloadAnchor = document.createElement("a");
      downloadAnchor.setAttribute("href", dataStr);
      downloadAnchor.setAttribute("download", `authclaw_signed_audit_export_${artifact.payload?.export_id || Date.now()}.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
      setExportStatus(`Signed ${artifact.payload?.record_count ?? 0} records with ${artifact.signature?.algorithm || "signature"}.`);
    } catch (err: unknown) {
      setExportStatus(getErrorMessage(err, "Signed export failed"));
    } finally {
      setSignedExportBusy(false);
    }
  };

  const verifySignedAudit = async (file: File) => {
    setVerifyBusy(true);
    setExportStatus(null);
    setVerifyResult(null);
    try {
      const artifact = JSON.parse(await file.text());
      const res = await fetch("/api/audit/export/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ artifact }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Verification failed");
      setVerifyResult(data);
    } catch (err: unknown) {
      setExportStatus(getErrorMessage(err, "Could not verify signed export"));
    } finally {
      setVerifyBusy(false);
      if (verifyInputRef.current) verifyInputRef.current.value = "";
    }
  };

  const handlePrevPage = () => {
    if (offset >= limit) {
      setOffset(offset - limit);
    }
  };

  const handleNextPage = () => {
    setOffset(offset + limit);
  };

  return (
    <div className="ac-page ac-page-audit space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-extrabold tracking-tight text-[#0E1726]">
            Audit Explorer
          </h1>
          <p className="text-[#6B7488] text-sm mt-1">
            Immutably log every proxy interaction with SHA-256 integrity-chain verification.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={fetchLogs}
            className="p-2 rounded-lg bg-[#F5F7FA] hover:bg-[#EEF1F6] text-[#475069] border border-[#E6E9F0] transition"
            title="Refresh logs"
          >
            <RefreshCw className="w-4 h-4" />
          </button>

          <button
            onClick={exportJSON}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-[#F5F7FA] hover:bg-[#EEF1F6] text-[#0E1726] border border-[#E6E9F0] text-xs font-semibold transition"
          >
            <FileDown className="w-4.5 h-4.5 text-indigo-400" />
            Export JSON
          </button>

          <button
            onClick={exportCSV}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-[#F5F7FA] hover:bg-[#EEF1F6] text-[#0E1726] border border-[#E6E9F0] text-xs font-semibold transition"
          >
            <Download className="w-4.5 h-4.5 text-emerald-400" />
            Export CSV
          </button>

          <button
            onClick={exportSignedAudit}
            disabled={signedExportBusy}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white border border-indigo-500/40 text-xs font-semibold transition disabled:opacity-50"
          >
            <ShieldCheck className="w-4.5 h-4.5" />
            {signedExportBusy ? "Signing..." : "Signed Export"}
          </button>

          <input
            ref={verifyInputRef}
            type="file"
            accept="application/json,.json"
            className="hidden"
            onChange={(event) => {
              const file = event.target.files?.[0];
              if (file) void verifySignedAudit(file);
            }}
          />
          <button
            onClick={() => verifyInputRef.current?.click()}
            disabled={verifyBusy}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-[#F5F7FA] hover:bg-[#EEF1F6] text-[#0E1726] border border-[#E6E9F0] text-xs font-semibold transition disabled:opacity-50"
          >
            <ShieldAlert className="w-4.5 h-4.5 text-sky-400" />
            {verifyBusy ? "Verifying..." : "Verify Export"}
          </button>
        </div>
      </div>

      {(exportStatus || verifyResult) && (
        <div className={`rounded-[20px] border p-4 text-xs ${
          verifyResult?.verified
            ? "border-emerald-500/20 bg-emerald-500/10 text-emerald-100"
            : verifyResult
              ? "border-red-500/20 bg-red-500/10 text-red-100"
              : "border-[#E6E9F0] bg-white text-[#475069]"
        }`}>
          {verifyResult ? (
            <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <div className="flex items-center gap-2 font-bold">
                  {verifyResult.verified ? <ShieldCheck className="w-4 h-4" /> : <ShieldAlert className="w-4 h-4" />}
                  {verifyResult.verified ? "Signed audit export verified" : "Signed audit export failed verification"}
                </div>
                <div className="mt-1 text-[11px] opacity-80">
                  {verifyResult.record_count} records - key {verifyResult.key_id} - signature {verifyResult.signature_valid ? "valid" : "invalid"} - chain {verifyResult.chain_valid ? "valid" : "invalid"}
                </div>
                {verifyResult.errors.length > 0 && (
                  <div className="mt-2 font-mono text-[10px] opacity-90">
                    {verifyResult.errors.slice(0, 3).join(" | ")}
                  </div>
                )}
              </div>
              <div className="font-mono text-[10px] opacity-70">
                Last hash {verifyResult.last_hash.slice(0, 16)}...
              </div>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-indigo-400" />
              {exportStatus}
            </div>
          )}
        </div>
      )}

      {/* Filters Panel */}
      <div className="rounded-[20px] border border-[#E6E9F0] bg-white p-5 shadow-xl space-y-4">
        <div className="flex items-center gap-2 text-[#475069] text-xs font-bold uppercase tracking-wider">
          <SlidersHorizontal className="w-4 h-4 text-indigo-400" />
          Search & Query Filters
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
          <div>
            <label className="block text-[10px] font-bold text-[#6B7488] uppercase mb-1.5">Action</label>
            <select
              value={actionFilter}
              onChange={(e) => { setActionFilter(e.target.value); setOffset(0); }}
              className="w-full px-3 py-2 rounded-lg bg-[#F5F7FA] border border-[#E6E9F0] text-[#0E1726] text-xs focus:outline-none focus:border-indigo-500/80 transition"
            >
              <option value="">All Actions</option>
              <option value="allow">ALLOW</option>
              <option value="test_request">TEST REQUEST</option>
              <option value="redact">REDACT</option>
              <option value="block">BLOCK</option>
              <option value="approval_allow">APPROVAL ALLOW</option>
            </select>
          </div>

          <div>
            <label className="block text-[10px] font-bold text-[#6B7488] uppercase mb-1.5">Actor ID</label>
            <div className="relative">
              <span className="absolute inset-y-0 left-0 pl-2.5 flex items-center pointer-events-none text-[#6B7488]">
                <Search className="w-3.5 h-3.5" />
              </span>
              <input
                type="text"
                value={actorFilter}
                onChange={(e) => setActorFilter(e.target.value)}
                placeholder="Search Actor UUID..."
                className="w-full pl-8 pr-3 py-2 rounded-lg bg-[#F5F7FA] border border-[#E6E9F0] text-[#0E1726] text-xs placeholder-[#A8B0C0] focus:outline-none focus:border-indigo-500/80 transition"
              />
            </div>
          </div>

          <div>
            <label className="block text-[10px] font-bold text-[#6B7488] uppercase mb-1.5">Date Start</label>
            <div className="relative">
              <input
                type="date"
                value={dateStart}
                onChange={(e) => setDateStart(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-[#F5F7FA] border border-[#E6E9F0] text-[#0E1726] text-xs focus:outline-none focus:border-indigo-500/80 transition"
              />
            </div>
          </div>

          <div>
            <label className="block text-[10px] font-bold text-[#6B7488] uppercase mb-1.5">Date End</label>
            <div className="relative">
              <input
                type="date"
                value={dateEnd}
                onChange={(e) => setDateEnd(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-[#F5F7FA] border border-[#E6E9F0] text-[#0E1726] text-xs focus:outline-none focus:border-indigo-500/80 transition"
              />
            </div>
          </div>
        </div>

        <div className="flex items-center justify-between pt-2 border-t border-[#E6E9F0] text-xs">
          <label className="flex items-center gap-2 text-[#6B7488] cursor-pointer">
            <input
              type="checkbox"
              checked={integrityCheck}
              onChange={(e) => setIntegrityCheck(e.target.checked)}
              className="rounded bg-[#F5F7FA] border-[#E6E9F0] text-indigo-500 focus:ring-0 focus:ring-offset-0"
            />
            Perform Cryptographic Chain Integrity Verification
          </label>
        </div>
      </div>

      {/* Logs Table */}
      <div className="rounded-[20px] bg-white border border-[#E6E9F0] shadow-xl overflow-hidden">
        <div className="overflow-x-auto">
          {loading ? (
            <div className="flex flex-col items-center justify-center min-h-[300px]">
              <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-indigo-500 mb-2" />
              <p className="text-xs text-[#6B7488]">Retrieving audit ledger...</p>
            </div>
          ) : error ? (
            <div className="p-12 text-center text-red-400 flex flex-col items-center justify-center min-h-[300px]">
              <AlertTriangle className="w-10 h-10 mb-3" />
              <h4 className="font-bold">Fetch Failed</h4>
              <p className="text-xs text-[#6B7488] mt-1">{error}</p>
            </div>
          ) : filteredRecords.length === 0 ? (
            <div className="p-12 text-center flex flex-col items-center justify-center min-h-[300px]">
              <ScrollText className="w-10 h-10 text-[#6B7488] mb-3" />
              <h4 className="text-sm font-semibold text-[#475069]">No data available yet</h4>
              <p className="text-[#6B7488] text-xs mt-1">
                No logs matched the selected filters or no traffic has been intercepted.
              </p>
              {auditSource === "postgres" && (
                <p className="mt-2 text-[11px] text-[#6B7488]">
                  Using Postgres fallback audit storage.
                </p>
              )}
            </div>
          ) : (
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-[#E6E9F0] bg-[#F5F7FA]/40 text-[#6B7488] font-bold uppercase tracking-wider text-[10px]">
                  <th className="px-6 py-4">Timestamp</th>
                  <th className="px-6 py-4">Actor ID</th>
                  <th className="px-6 py-4">Action / Rule</th>
                  <th className="px-6 py-4">Provider / Model</th>
                  <th className="px-6 py-4">Integrity Badge</th>
                  <th className="px-6 py-4">Affected Frameworks</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#E6E9F0]/50">
                {filteredRecords.map((log) => {
                  const isBlock = log.action.toLowerCase() === "block";
                  return (
                    <tr
                      key={log.record_id}
                      onClick={() => setSelectedRecord(log)}
                      className="hover:bg-[#F5F7FA]/30 transition-colors cursor-pointer"
                    >
                      <td className="px-6 py-4 font-mono text-[#6B7488]">
                        {formatDateTime(log.timestamp)}
                      </td>
                      <td className="px-6 py-4 font-mono text-[#475069] select-all" title={log.actor_id}>
                        {log.actor_id ? `${log.actor_id.slice(0, 8)}...` : "System"}
                      </td>
                      <td className="px-6 py-4">
                        <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold ${
                          isBlock
                            ? "bg-red-500/10 border border-red-500/20 text-red-400"
                            : "bg-emerald-500/10 border border-emerald-500/20 text-emerald-400"
                        }`}>
                          {log.action.toUpperCase()}
                        </span>
                        {log.reason && log.reason !== "None" && (
                          <div className="text-[10px] text-[#6B7488] mt-1 max-w-[200px] truncate" title={log.reason}>
                            {log.reason}
                          </div>
                        )}
                      </td>
                      <td className="px-6 py-4">
                        <div className="font-semibold text-[#475069] capitalize">{log.provider}</div>
                        <div className="text-[10px] text-[#6B7488] font-mono mt-0.5">{log.model}</div>
                      </td>
                      <td className="px-6 py-4">
                        {integrityCheck && integrityCheckedByBackend ? (
                          log.chain_valid ? (
                            <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-emerald-400">
                              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" />
                              Verified
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-red-400 animate-pulse">
                              <XCircle className="w-3.5 h-3.5 text-red-500" />
                              Tampered
                            </span>
                          )
                        ) : auditSource === "postgres" ? (
                          <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-sky-400">
                            <ScrollText className="w-3.5 h-3.5" />
                            Stored
                          </span>
                        ) : (
                          <span className="text-[#6B7488] text-[10px]">Skipped</span>
                        )}
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex flex-wrap gap-1">
                          {log.frameworks_affected && log.frameworks_affected.length > 0 ? (
                            log.frameworks_affected.map((f) => (
                              <span key={f} className="px-1.5 py-0.5 rounded bg-[#F5F7FA] text-[10px] text-[#6B7488] border border-[#E6E9F0] font-semibold">
                                {f}
                              </span>
                            ))
                          ) : (
                            <span className="text-[#6B7488]">-</span>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>

        {/* Pagination Toolbar */}
        <div className="px-6 py-4 border-t border-[#E6E9F0] bg-[#F5F7FA] flex items-center justify-between text-xs text-[#6B7488]">
          <div>
            Showing <span className="font-semibold text-[#0E1726]">{filteredRecords.length}</span> entries
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handlePrevPage}
              disabled={offset === 0 || loading}
              className="p-1.5 rounded bg-[#F5F7FA] hover:bg-[#EEF1F6] border border-[#E6E9F0] text-[#0E1726] disabled:opacity-40 disabled:pointer-events-none transition"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="font-mono text-[#475069]">
              Page {Math.floor(offset / limit) + 1}
            </span>
            <button
              onClick={handleNextPage}
              disabled={records.length < limit || loading}
              className="p-1.5 rounded bg-[#F5F7FA] hover:bg-[#EEF1F6] border border-[#E6E9F0] text-[#0E1726] disabled:opacity-40 disabled:pointer-events-none transition"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Slide-out Event Inspector Panel */}
      {selectedRecord ? (
        <div className="fixed inset-0 z-50 flex justify-end">
          {/* Backdrop */}
          <div
            className="fixed inset-0 bg-black/60 backdrop-blur-xs transition-opacity"
            onClick={() => setSelectedRecord(null)}
          />

          {/* Panel Container */}
          <div className="relative w-full max-w-lg md:max-w-xl bg-white border-l border-[#E6E9F0] shadow-2xl p-6 flex flex-col h-full overflow-y-auto text-xs text-[#475069]">
            {/* Header */}
            <div className="flex justify-between items-center mb-6 border-b border-[#E6E9F0] pb-4">
              <div>
                <h3 className="text-sm font-bold text-[#0E1726] flex items-center gap-1.5">
                  <ScrollText className="w-4 h-4 text-indigo-400" />
                  Event Inspector
                </h3>
                <p className="text-[10px] text-[#6B7488] mt-0.5 font-medium">
                  Telemetry and cryptographic integrity validation.
                </p>
              </div>
              <button
                onClick={() => setSelectedRecord(null)}
                className="p-1 rounded-lg hover:bg-[#F5F7FA] text-[#6B7488] hover:text-[#0E1726] transition cursor-pointer"
              >
                <X className="w-4.5 h-4.5" />
              </button>
            </div>

            {/* Cryptographic Badge */}
            <div className="p-4 rounded-xl border border-[#E6E9F0] bg-[#F5F7FA] mb-6 flex items-center justify-between">
              <div>
                <span className="text-[9px] font-black uppercase text-[#6B7488] block tracking-wider mb-1">
                  CRYPTOGRAPHIC INTEGRITY STATUS
                </span>
                {integrityCheck && integrityCheckedByBackend ? (
                  selectedRecord.chain_valid ? (
                    <span className="inline-flex items-center gap-1.5 text-xs font-bold text-emerald-400 bg-emerald-500/10 border border-emerald-500/25 px-2.5 py-0.5 rounded-full">
                      <ShieldCheck className="w-3.5 h-3.5" />
                      Chain Valid & Verified
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1.5 text-xs font-bold text-red-400 bg-red-500/10 border border-red-500/25 px-2.5 py-0.5 rounded-full animate-pulse">
                      <ShieldAlert className="w-3.5 h-3.5" />
                      Verification Failed (Tampered)
                    </span>
                  )
                ) : auditSource === "postgres" ? (
                  <span className="inline-flex items-center gap-1.5 text-xs font-bold text-sky-400 bg-sky-500/10 border border-sky-500/25 px-2.5 py-0.5 rounded-full">
                    <ScrollText className="w-3.5 h-3.5" />
                    Stored in Postgres Fallback
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1.5 text-xs font-bold text-[#6B7488] bg-[#F5F7FA] border border-[#E6E9F0] px-2.5 py-0.5 rounded-full">
                    Verification Skipped
                  </span>
                )}
              </div>
              <span className="text-[10px] font-bold text-[#6B7488] uppercase px-2 py-0.5 rounded bg-[#F5F7FA] border border-[#E6E9F0]">
                Source: {inspectedProvider ? "LLM Proxy" : "System Audit"}
              </span>
            </div>

            {/* Telemetry and Details */}
            <div className="space-y-5">
              {/* Event Metadata */}
              <div>
                <h4 className="text-[10px] font-bold uppercase tracking-wider text-indigo-400 mb-2.5">
                  Event Metadata
                </h4>
                <div className="grid grid-cols-2 gap-3.5 p-4 rounded-xl border border-[#E6E9F0] bg-[#F5F7FA] text-[11px]">
                  <div>
                    <span className="text-[#6B7488] text-[9px] font-black uppercase">RECORD ID</span>
                    <div className="flex items-center gap-1 mt-0.5 font-mono text-[10px] text-[#475069]">
                      <span>{selectedRecord.record_id}</span>
                      <button
                        onClick={() => handleCopy(selectedRecord.record_id, 'record_id')}
                        className="p-0.5 text-[#6B7488] hover:text-[#0E1726] transition cursor-pointer"
                      >
                        {copiedField === 'record_id' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      </button>
                    </div>
                  </div>
                  <div>
                    <span className="text-[#6B7488] text-[9px] font-black uppercase">REQUEST CORRELATION ID</span>
                    <p className="font-mono text-[10px] text-[#475069] mt-0.5">
                      {inspectedRequestId}
                    </p>
                  </div>
                  <div>
                    <span className="text-[#6B7488] text-[9px] font-black uppercase">TIMESTAMP</span>
                    <p className="text-[#475069] mt-0.5 font-mono">
                      {formatDateTime(selectedRecord.timestamp)}
                    </p>
                  </div>
                  <div>
                    <span className="text-[#6B7488] text-[9px] font-black uppercase">ACTION</span>
                    <p className="mt-0.5 font-semibold">
                      <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold ${
                        inspectedAction.toLowerCase() === 'block'
                          ? 'bg-red-500/10 border border-red-500/20 text-red-400'
                          : 'bg-emerald-500/10 border border-emerald-500/20 text-emerald-400'
                      }`}>
                        {inspectedAction.toUpperCase()}
                      </span>
                    </p>
                  </div>
                </div>
              </div>

              {/* Actor Details */}
              <div>
                <h4 className="text-[10px] font-bold uppercase tracking-wider text-indigo-400 mb-2.5">
                  Actor Details
                </h4>
                <div className="grid grid-cols-2 gap-3.5 p-4 rounded-xl border border-[#E6E9F0] bg-[#F5F7FA] text-[11px]">
                  <div>
                    <span className="text-[#6B7488] text-[9px] font-black uppercase">ACTOR ID</span>
                    <p className="font-mono text-[10px] text-[#475069] mt-0.5 truncate select-all" title={inspectedActorId}>
                      {inspectedActorId}
                    </p>
                  </div>
                  <div>
                    <span className="text-[#6B7488] text-[9px] font-black uppercase">ACTOR TYPE</span>
                    <p className="text-[#475069] mt-0.5 capitalize font-semibold">
                      {inspectedActorType}
                    </p>
                  </div>
                </div>
              </div>

              {/* API Interception Details */}
              {inspectedProvider ? (
                <div>
                  <h4 className="text-[10px] font-bold uppercase tracking-wider text-indigo-400 mb-2.5">
                    API Telemetry
                  </h4>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3.5 p-4 rounded-xl border border-[#E6E9F0] bg-[#F5F7FA] text-[11px]">
                    <div>
                      <span className="text-[#6B7488] text-[9px] font-black uppercase">PROVIDER</span>
                      <p className="font-semibold text-[#475069] capitalize mt-0.5">
                        {selectedRecord.provider}
                      </p>
                    </div>
                    <div>
                      <span className="text-[#6B7488] text-[9px] font-black uppercase">MODEL</span>
                      <p className="font-mono text-[10px] text-[#6B7488] mt-0.5">
                        {selectedRecord.model}
                      </p>
                    </div>
                    <div>
                      <span className="text-[#6B7488] text-[9px] font-black uppercase">STATUS CODE</span>
                      <p className="font-semibold text-[#475069] mt-0.5">
                        {selectedRecord.response_status || "N/A"}
                      </p>
                    </div>
                    <div>
                      <span className="text-[#6B7488] text-[9px] font-black uppercase">DURATION</span>
                      <p className="font-semibold text-[#475069] mt-0.5">
                        {selectedRecord.duration_ms !== undefined ? `${selectedRecord.duration_ms} ms` : "N/A"}
                      </p>
                    </div>
                  </div>
                </div>
              ) : null}

              {/* Cryptographic Chain Details */}
              <div>
                <h4 className="text-[10px] font-bold uppercase tracking-wider text-indigo-400 mb-2.5">
                  Cryptographic Chain Hashes
                </h4>
                <div className="space-y-3.5 p-4 rounded-xl border border-[#E6E9F0] bg-[#F5F7FA] text-[10px] font-mono">
                  <div>
                    <div className="flex justify-between items-center mb-1">
                      <span className="text-[#6B7488] text-[9px] font-black uppercase font-sans">PRIOR HASH</span>
                      <button
                        onClick={() => handleCopy(selectedRecord.prior_hash || '', 'prior_hash')}
                        className="p-0.5 text-[#6B7488] hover:text-[#0E1726] transition flex items-center gap-1 cursor-pointer font-sans text-[8px] font-bold"
                      >
                        {copiedField === 'prior_hash' ? <Check className="w-2.5 h-2.5 text-emerald-400" /> : <Copy className="w-2.5 h-2.5" />}
                        Copy
                      </button>
                    </div>
                    <div className="p-2 bg-[#F5F7FA] rounded border border-[#E6E9F0] text-[#6B7488] break-all select-all">
                      {selectedRecord.prior_hash || "GENESIS"}
                    </div>
                  </div>

                  <div>
                    <div className="flex justify-between items-center mb-1">
                      <span className="text-[#6B7488] text-[9px] font-black uppercase font-sans">INTEGRITY HASH</span>
                      <button
                        onClick={() => handleCopy(selectedRecord.integrity_hash || '', 'integrity_hash')}
                        className="p-0.5 text-[#6B7488] hover:text-[#0E1726] transition flex items-center gap-1 cursor-pointer font-sans text-[8px] font-bold"
                      >
                        {copiedField === 'integrity_hash' ? <Check className="w-2.5 h-2.5 text-emerald-400" /> : <Copy className="w-2.5 h-2.5" />}
                        Copy
                      </button>
                    </div>
                    <div className="p-2 bg-[#F5F7FA] rounded border border-[#E6E9F0] text-[#6B7488] break-all select-all">
                      {selectedRecord.integrity_hash || "N/A"}
                    </div>
                  </div>
                </div>
              </div>

              {/* Execution Trace */}
              {selectedRecord.execution_trace && selectedRecord.execution_trace !== "[]" && (
                <div>
                  <h4 className="text-[10px] font-bold uppercase tracking-wider text-indigo-400 mb-2.5">
                    Execution Trace
                  </h4>
                  <div className="p-4 rounded-xl border border-[#E6E9F0] bg-[#F5F7FA] space-y-2 max-h-[180px] overflow-y-auto">
                    {(() => {
                      try {
                        const parsed = typeof selectedRecord.execution_trace === 'string'
                          ? JSON.parse(selectedRecord.execution_trace)
                          : selectedRecord.execution_trace;
                        if (Array.isArray(parsed)) {
                          return parsed.map((step: unknown, idx: number) => (
                            <div key={idx} className="flex gap-2 items-start py-1 text-[11px] leading-relaxed border-b border-[#E6E9F0] last:border-b-0 pb-1.5 last:pb-0">
                              <span className="w-4.5 h-4.5 rounded bg-indigo-500/10 text-indigo-400 flex items-center justify-center font-bold text-[9px] flex-shrink-0">
                                {idx + 1}
                              </span>
                              <span className="font-mono text-[#475069]">{typeof step === 'object' ? JSON.stringify(step) : String(step)}</span>
                            </div>
                          ));
                        }
                        return <pre className="font-mono text-[#6B7488] break-all">{String(selectedRecord.execution_trace)}</pre>;
                      } catch {
                        return <pre className="font-mono text-[#6B7488] break-all">{String(selectedRecord.execution_trace)}</pre>;
                      }
                    })()}
                  </div>
                </div>
              )}

              {selectedRecord.action?.startsWith("workflow:") && (() => {
                const trace = parseExecutionTrace(selectedRecord.execution_trace);
                const workflowId = traceValue(trace, "workflow_id");
                const actionId = traceValue(trace, "action_id");
                const control = traceValue(trace, "control");
                const attempt = traceValue(trace, "attempt");
                const actionStatus = traceValue(trace, "action_status");
                const actionError = traceValue(trace, "error");
                const transition = traceValue(trace, "transition") || selectedRecord.reason?.replace(/\s*\[[^\]]+\]\s*$/, "") || "Workflow transition";
                const status = selectedRecord.reason?.match(/\[([^\]]+)\]/)?.[1] || selectedRecord.action.replace("workflow:", "");
                const isRemediationAction = selectedRecord.action.startsWith("workflow:remediation_action_");
                const isRollback = transition.includes("ROLLBACK");
                const isFailure = status.toLowerCase().includes("fail") || transition.includes("FAILED");

                return (
                  <div>
                    <h4 className="text-[10px] font-bold uppercase tracking-wider text-indigo-400 mb-2.5">
                      Workflow State Transition
                    </h4>
                    <div className="p-4 rounded-xl border border-[#E6E9F0] bg-[#F5F7FA] space-y-3 text-[11px]">
                      <div className="flex items-center justify-between gap-3">
                        <div className="min-w-0">
                          <span className="text-[#6B7488] text-[9px] font-black uppercase">Transition</span>
                          <p className="font-mono text-[#475069] mt-0.5 break-all">{transition}</p>
                        </div>
                        <span className={`shrink-0 inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[9px] font-bold uppercase ${
                          isFailure
                            ? "bg-red-500/10 border-red-500/20 text-red-400"
                            : isRollback
                              ? "bg-amber-500/10 border-amber-500/20 text-amber-400"
                              : "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
                        }`}>
                          {isFailure ? <XCircle className="w-3 h-3" /> : <CheckCircle2 className="w-3 h-3" />}
                          {status}
                        </span>
                      </div>

                      {workflowId && (
                        <div>
                          <span className="text-[#6B7488] text-[9px] font-black uppercase">Workflow ID</span>
                          <p className="font-mono text-[10px] text-[#475069] mt-0.5 break-all select-all">{workflowId}</p>
                        </div>
                      )}

                      {isRemediationAction && (
                        <div className="grid grid-cols-2 gap-3 rounded border border-[#E6E9F0] bg-[#F5F7FA]/40 p-3">
                          <div className="col-span-2">
                            <span className="text-[#6B7488] text-[9px] font-black uppercase">Action ID</span>
                            <p className="font-mono text-[10px] text-[#475069] mt-0.5 break-all select-all">{actionId || "N/A"}</p>
                          </div>
                          <div className="col-span-2">
                            <span className="text-[#6B7488] text-[9px] font-black uppercase">Control</span>
                            <p className="font-mono text-[10px] text-[#475069] mt-0.5 break-all">{control || "N/A"}</p>
                          </div>
                          <div>
                            <span className="text-[#6B7488] text-[9px] font-black uppercase">Attempt</span>
                            <p className="font-semibold text-[#475069] mt-0.5">{attempt || "0"}</p>
                          </div>
                          <div>
                            <span className="text-[#6B7488] text-[9px] font-black uppercase">Action Status</span>
                            <p className="font-semibold text-[#475069] mt-0.5">{actionStatus || status}</p>
                          </div>
                          {actionError && (
                            <div className="col-span-2 rounded border border-red-500/20 bg-red-500/10 p-2 text-[10px] text-red-300">
                              {actionError}
                            </div>
                          )}
                        </div>
                      )}

                      {isRollback && (
                        <div className="rounded border border-amber-500/15 bg-amber-500/10 p-2 text-[10px] text-amber-300 leading-normal">
                          Rollback path entered. Check the remediation workflow inspector for per-action rollback results.
                        </div>
                      )}
                    </div>
                  </div>
                );
              })()}

              {/* Custom Attributes (Supporting future/arbitrary event types) */}
              {(() => {
                const STANDARD_FIELDS = new Set([
                  "record_id", "request_id", "timestamp", "action", "actor_id", "actor_type",
                  "provider", "model", "response_status", "duration_ms", "prior_hash",
                  "integrity_hash", "execution_trace", "chain_valid", "frameworks_affected"
                ]);
                const recordValues = selectedRecord as unknown as Record<string, unknown>;
                const customKeys = Object.keys(recordValues).filter(key => !STANDARD_FIELDS.has(key));
                if (customKeys.length === 0) return null;
                return (
                  <div>
                    <h4 className="text-[10px] font-bold uppercase tracking-wider text-indigo-400 mb-2.5">
                      Custom Attributes
                    </h4>
                    <div className="grid grid-cols-2 gap-3.5 p-4 rounded-xl border border-[#E6E9F0] bg-[#F5F7FA] text-[11px]">
                      {customKeys.map(key => (
                        <div key={key} className="overflow-hidden">
                          <span className="text-[#6B7488] text-[9px] font-black uppercase block truncate" title={key}>
                            {key}
                          </span>
                          <span className="font-mono text-[10px] text-[#475069] mt-0.5 break-all block">
                            {formatAuditValue(recordValues[key])}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })()}

              {/* Raw JSON Viewer */}
              <div>
                <h4 className="text-[10px] font-bold uppercase tracking-wider text-indigo-400 mb-2.5">
                  Raw Event JSON
                </h4>
                <div className="p-4 rounded-xl border border-[#E6E9F0] bg-[#F5F7FA] overflow-x-auto max-h-[280px]">
                  <pre className="font-mono text-[10px] text-[#6B7488] select-all leading-normal">
                    {JSON.stringify(selectedRecord, null, 2)}
                  </pre>
                </div>
              </div>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
