"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertCircle,
  Award,
  CheckCircle2,
  ChevronRight,
  Clipboard,
  Database,
  Download,
  ExternalLink,
  FileCheck,
  Link2,
  RefreshCw,
  ShieldCheck,
  XCircle,
} from "lucide-react";
import { flashCopy } from "@/lib/clipboard";
import { getErrorMessage } from "@/lib/errors";
import { TrustSummary } from "@/components/trust-summary";
import type { TrustSummary as TrustSummaryData } from "@/lib/trust-summary";
import { readinessLabel } from "@/lib/ui-format";

type FrameworkId = "SOC2" | "GDPR" | "HIPAA";

interface TraceItem {
  id?: string;
  record_id?: string;
  title?: string;
  type?: string;
  severity?: string;
  status?: string;
  action?: string;
  provider?: string;
  source_reference?: string;
  created_at: string;
  scope: "control" | "framework";
  url: string;
}

interface ControlTraceability {
  evidence_total: number;
  finding_total: number;
  audit_event_total: number;
  evidence: TraceItem[];
  findings: TraceItem[];
  audit_events: TraceItem[];
  links: {
    evidence_url: string;
    findings_url: string;
    audit_url: string;
  };
}

interface ControlScore {
  id: string;
  name: string;
  description: string;
  weight: number;
  score: number;
  status: "compliant" | "partial" | "non_compliant";
  evidence: string[];
  gaps: string[];
  traceability?: ControlTraceability;
}

interface FrameworkScore {
  framework: FrameworkId;
  score: number;
  readiness_level: string;
  controls: ControlScore[];
  metrics: {
    evidence_count: number;
    audit_event_count: number;
    framework_audit_event_count: number;
    audit_hash_count: number;
    redaction_count: number;
    active_policy_count: number;
    active_gateway_count: number;
    pending_approvals: number;
    open_findings: number;
    critical_findings: number;
    high_findings: number;
    resolved_findings: number;
  };
  generated_at: string;
}

interface ComplianceScoreState {
  overall_score: number;
  readiness_level: string;
  frameworks: FrameworkScore[];
  generated_at: string;
  trust_summary?: TrustSummaryData;
}

interface ScoreHistoryItem {
  framework: FrameworkId;
  snapshot_date: string;
  overall_score: number;
  readiness_level: string;
  evidence_count: number;
  audit_event_count: number;
  open_findings: number;
  critical_findings: number;
  generated_at: string;
}

interface TrustCenterShare {
  id: string;
  label: string;
  auditor_email: string;
  frameworks: FrameworkId[];
  permissions: string[];
  status: "active" | "revoked" | "expired";
  token_prefix: string;
  expires_at: string;
  created_at: string;
  revoked_at: string;
  last_accessed_at: string;
  access_count: number;
}

interface CreatedTrustCenterShare {
  share: TrustCenterShare;
  token: string;
  url: string;
}

const frameworkMeta: Record<FrameworkId, { name: string; desc: string; accent: string }> = {
  SOC2: {
    name: "SOC 2 Type II",
    desc: "Security, availability, confidentiality, monitoring, and remediation controls.",
    accent: "text-emerald-300",
  },
  GDPR: {
    name: "GDPR",
    desc: "Privacy-by-design, processing records, security controls, and risk evidence.",
    accent: "text-sky-300",
  },
  HIPAA: {
    name: "HIPAA Security Rule",
    desc: "Access, audit, integrity, and transmission safeguards for PHI-like workflows.",
    accent: "text-amber-200",
  },
};

const statusClass = (status: ControlScore["status"]) => {
  if (status === "compliant") return "bg-emerald-500/10 border-emerald-500/20 text-emerald-300";
  if (status === "partial") return "bg-amber-500/10 border-amber-500/20 text-amber-200";
  return "bg-red-500/10 border-red-500/20 text-red-300";
};

const traceScopeLabel = (scope: TraceItem["scope"]) => scope === "control" ? "matched" : "framework";

function TraceList({ title, items, empty }: { title: string; items: TraceItem[]; empty: string }) {
  return (
    <div className="min-w-0">
      <div className="mb-2 text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">{title}</div>
      <div className="space-y-1.5">
        {items.length === 0 ? (
          <div className="rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] px-3 py-2 text-[10px] text-[#6B7488]">{empty}</div>
        ) : (
          items.slice(0, 3).map((item) => (
            <a
              key={item.id || item.record_id || `${item.action}-${item.created_at}`}
              href={item.url}
              className="block rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] px-3 py-2 text-[10px] text-[#475069] hover:border-indigo-300 hover:bg-white"
            >
              <div className="flex items-center justify-between gap-2">
                <span className="truncate font-semibold text-[#0E1726]">
                  {item.title || item.type || item.action || item.id || item.record_id}
                </span>
                <span className="shrink-0 rounded border border-[#E6E9F0] bg-white px-1.5 py-0.5 uppercase text-[#6B7488]">
                  {traceScopeLabel(item.scope)}
                </span>
              </div>
              <div className="mt-1 truncate font-mono text-[#6B7488]">
                {item.source_reference || item.status || item.provider || item.record_id || item.id}
              </div>
            </a>
          ))
        )}
      </div>
    </div>
  );
}

export default function FrameworksPage() {
  const [scores, setScores] = useState<ComplianceScoreState | null>(null);
  const [history, setHistory] = useState<ScoreHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeFramework, setActiveFramework] = useState<FrameworkId>("SOC2");
  const [exporting, setExporting] = useState(false);
  const [exportMessage, setExportMessage] = useState<string | null>(null);
  const [trustShares, setTrustShares] = useState<TrustCenterShare[]>([]);
  const [shareMessage, setShareMessage] = useState<string | null>(null);
  const [shareBusy, setShareBusy] = useState(false);
  const [canManageShares, setCanManageShares] = useState(false);
  const [createdShare, setCreatedShare] = useState<CreatedTrustCenterShare | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [shareForm, setShareForm] = useState({
    label: "Auditor readiness review",
    auditorEmail: "",
    expiresInDays: 30,
    frameworks: ["SOC2", "GDPR", "HIPAA"] as FrameworkId[],
  });

  const fetchScores = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [scoreRes, frameworkRes] = await Promise.all([
        fetch("/api/compliance-scores"),
        fetch(`/api/compliance-scores/${activeFramework}`),
      ]);
      if (scoreRes.status === 401 || frameworkRes.status === 401) {
        window.location.href = "/login";
        return;
      }
      if (!scoreRes.ok || !frameworkRes.ok) throw new Error("Failed to load framework scores");
      const scoreData = await scoreRes.json() as ComplianceScoreState;
      const frameworkData = await frameworkRes.json() as FrameworkScore;
      setScores({
        ...scoreData,
        frameworks: scoreData.frameworks.map((item) => item.framework === activeFramework ? frameworkData : item),
      });
      const historyRes = await fetch(`/api/compliance-scores/history?framework=${activeFramework}&days=30`);
      if (historyRes.status === 401) {
        window.location.href = "/login";
        return;
      }
      if (historyRes.ok) {
        const historyData = await historyRes.json();
        setHistory(historyData.items || []);
      }
    } catch (err: unknown) {
      const message = getErrorMessage(err, "Failed to load compliance scoring data");
      console.warn("Frameworks fetchScores failed:", message);
      setError(message);
    } finally {
      setLoading(false);
    }
  }, [activeFramework]);

  const fetchTrustShares = useCallback(async () => {
    try {
      const res = await fetch("/api/trust-center/shares");
      if (res.status === 401) {
        window.location.href = "/login";
        return;
      }
      if (!res.ok) throw new Error("Failed to load Trust Center shares");
      setTrustShares(await res.json());
    } catch (err: unknown) {
      const message = getErrorMessage(err, "Failed to load Trust Center shares");
      console.warn("Trust Center shares fetch failed:", message);
      setShareMessage(message);
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void fetchScores();
    }, 0);
    return () => window.clearTimeout(timer);
  }, [fetchScores]);

  useEffect(() => {
    const timer = window.setTimeout(async () => {
      const session = await fetch("/api/auth/session").then((response) => response.json()).catch(() => ({}));
      const allowed = ["owner", "admin"].includes(String(session.role || "").toLowerCase());
      setCanManageShares(allowed);
      if (allowed) void fetchTrustShares();
    }, 0);
    return () => window.clearTimeout(timer);
  }, [fetchTrustShares]);

  const activeScore = useMemo(
    () => scores?.frameworks.find((item) => item.framework === activeFramework) || null,
    [activeFramework, scores],
  );

  const handleSignedExport = async () => {
    setExporting(true);
    setExportMessage(null);
    try {
      const res = await fetch("/api/audit/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ framework: activeFramework }),
      });
      const artifact = await res.json();
      if (!res.ok) throw new Error(artifact.error || "Signed export failed");
      const dataStr = "data:application/json;charset=utf-8," + encodeURIComponent(JSON.stringify(artifact, null, 2));
      const downloadAnchor = document.createElement("a");
      downloadAnchor.setAttribute("href", dataStr);
      downloadAnchor.setAttribute("download", `authclaw_${activeFramework.toLowerCase()}_signed_audit_export_${artifact.payload?.export_id || Date.now()}.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
      setExportMessage(`Signed ${artifact.payload?.record_count ?? 0} ${activeFramework} audit records.`);
    } catch (err: unknown) {
      setExportMessage(getErrorMessage(err, "Signed export failed"));
    } finally {
      setExporting(false);
    }
  };

  const toggleShareFramework = (framework: FrameworkId) => {
    setShareForm((current) => {
      const present = current.frameworks.includes(framework);
      const frameworks = present
        ? current.frameworks.filter((item) => item !== framework)
        : [...current.frameworks, framework];
      return { ...current, frameworks: frameworks.length ? frameworks : [framework] };
    });
  };

  const handleCreateTrustShare = async () => {
    setShareBusy(true);
    setShareMessage(null);
    setCreatedShare(null);
    try {
      const res = await fetch("/api/trust-center/shares", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          label: shareForm.label,
          auditor_email: shareForm.auditorEmail || null,
          frameworks: shareForm.frameworks,
          expires_in_days: shareForm.expiresInDays,
        }),
      });
      const payload = await res.json();
      if (!res.ok) throw new Error(payload.detail || payload.error || "Failed to create auditor link");
      setCreatedShare(payload);
      setShareMessage("Auditor Trust Center link created. Copy it now; the raw token is only shown once.");
      await fetchTrustShares();
    } catch (err: unknown) {
      setShareMessage(getErrorMessage(err, "Failed to create auditor link"));
    } finally {
      setShareBusy(false);
    }
  };

  const handleRevokeTrustShare = async (shareId: string) => {
    setShareBusy(true);
    setShareMessage(null);
    try {
      const res = await fetch(`/api/trust-center/shares/${encodeURIComponent(shareId)}/revoke`, { method: "POST" });
      const payload = await res.json();
      if (!res.ok) throw new Error(payload.detail || payload.error || "Failed to revoke auditor link");
      setShareMessage("Auditor link revoked.");
      await fetchTrustShares();
    } catch (err: unknown) {
      setShareMessage(getErrorMessage(err, "Failed to revoke auditor link"));
    } finally {
      setShareBusy(false);
    }
  };

  const copyTrustCenterText = async (id: string, value: string) => {
    const ok = await flashCopy(value, setCopied, id, null, 1500);
    if (!ok) return;
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-extrabold tracking-tight text-[#0E1726]">
            Compliance Frameworks
          </h1>
          <p className="text-[#6B7488] text-sm mt-1">
            Live readiness scores from evidence, findings, audit-chain events, redactions, policies, and approvals.
          </p>
        </div>

        <button
          onClick={fetchScores}
          className="self-start sm:self-center p-2 rounded-lg bg-[#F5F7FA] hover:bg-[#EEF1F6] text-[#475069] border border-[#E6E9F0] transition"
          title="Refresh framework statistics"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/20 text-red-200 text-xs flex items-center gap-3">
          <AlertCircle className="w-4.5 h-4.5 text-red-400 flex-shrink-0" />
          <p>{error}</p>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {(Object.keys(frameworkMeta) as FrameworkId[]).map((framework) => {
          const score = scores?.frameworks.find((item) => item.framework === framework);
          const active = activeFramework === framework;
          return (
            <button
              key={framework}
              onClick={() => setActiveFramework(framework)}
              className={`text-left relative overflow-hidden rounded-[20px] border p-6 shadow-xl transition group ${
                active ? "bg-indigo-950/15 border-indigo-500/50" : "bg-white border-[#E6E9F0] hover:border-[#E6E9F0]/80"
              }`}
            >
              <div className="flex justify-between items-start">
                <span className={`p-2 rounded-xl border ${
                  active ? "bg-indigo-900/30 border-indigo-500/40 text-indigo-300" : "bg-[#F5F7FA] border-[#E6E9F0]/50 text-[#6B7488]"
                }`}>
                  <Award className="w-5 h-5" />
                </span>

                <div className="text-right">
                  <span className={`text-2xl font-black ${frameworkMeta[framework].accent}`}>
                    {loading ? "-" : `${score?.score ?? 0}%`}
                  </span>
                  <span className="block text-[8px] text-[#6B7488] font-bold uppercase tracking-wider mt-0.5">
                    {score ? readinessLabel(score.readiness_level) : "NO DATA"}
                  </span>
                </div>
              </div>

              <h3 className="text-sm font-bold text-[#0E1726] mt-4 group-hover:text-indigo-300 transition">{frameworkMeta[framework].name}</h3>
              <p className="text-[#6B7488] text-xs mt-1 leading-relaxed">{frameworkMeta[framework].desc}</p>

              <div className="w-full bg-[#F5F7FA]/60 h-1.5 rounded-full mt-4 overflow-hidden">
                <div
                  className="bg-indigo-500 h-full rounded-full transition-all duration-500"
                  style={{ width: `${score?.score ?? 0}%` }}
                />
              </div>
            </button>
          );
        })}
      </div>

      <TrustSummary summary={scores?.trust_summary} />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-4">
          <div className="rounded-[20px] bg-white border border-[#E6E9F0] shadow-xl overflow-hidden">
            <div className="px-6 py-4 border-b border-[#E6E9F0] bg-[#F5F7FA] flex items-center justify-between">
              <h3 className="text-sm font-bold text-[#0E1726] uppercase tracking-wider flex items-center gap-2">
                <ShieldCheck className="w-4.5 h-4.5 text-indigo-400" />
                {activeFramework} Live Control Scores
              </h3>
              <span className="text-[10px] text-[#6B7488] font-bold">
                {activeScore?.controls.length || 0} controls
              </span>
            </div>

            {loading || !activeScore ? (
              <div className="p-8 flex justify-center">
                <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-indigo-500" />
              </div>
            ) : (
              <div className="divide-y divide-[#E6E9F0]/60">
                {activeScore.controls.map((control) => (
                  <div key={control.id} className="p-6 space-y-3 hover:bg-[#F5F7FA]/10 transition-colors">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold font-mono text-indigo-300 bg-indigo-500/5 px-2 py-0.5 rounded border border-indigo-500/10">
                          {control.id}
                        </span>
                        <h4 className="text-sm font-bold text-[#0E1726]">{control.name}</h4>
                      </div>

                      <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[9px] font-bold border ${statusClass(control.status)}`}>
                        {control.status === "compliant" && <CheckCircle2 className="w-3 h-3" />}
                        {control.status === "partial" && <AlertCircle className="w-3 h-3" />}
                        {control.status === "non_compliant" && <XCircle className="w-3 h-3" />}
                        {control.status.replace("_", " ").toUpperCase()} - {control.score}%
                      </span>
                    </div>

                    <p className="text-[#6B7488] text-xs leading-relaxed">{control.description}</p>

                    <div className="h-1.5 w-full rounded-full bg-[#F5F7FA] overflow-hidden">
                      <div className="h-full rounded-full bg-indigo-500" style={{ width: `${control.score}%` }} />
                    </div>

                    <div className="grid gap-3 md:grid-cols-2">
                      <div>
                        <p className="text-[10px] font-bold text-[#6B7488] uppercase tracking-wider">Evidence Signals</p>
                        <div className="mt-1.5 flex flex-col gap-1.5">
                          {(control.evidence.length ? control.evidence : ["No evidence signal yet"]).map((item) => (
                            <div key={item} className="flex items-center gap-2 text-xs text-[#475069]">
                              <ChevronRight className="w-3 h-3 text-indigo-500 flex-shrink-0" />
                              <span className="font-mono bg-[#F5F7FA] px-2 py-0.5 rounded border border-[#E6E9F0] flex items-center gap-1.5">
                                <Database className="w-3 h-3 text-indigo-400" />
                                {item}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                      <div>
                        <p className="text-[10px] font-bold text-[#6B7488] uppercase tracking-wider">Gaps</p>
                        <div className="mt-1.5 flex flex-col gap-1.5">
                          {(control.gaps.length ? control.gaps : ["No active gap"]).map((item) => (
                            <div key={item} className="flex items-center gap-2 text-xs text-[#6B7488]">
                              <ChevronRight className="w-3 h-3 text-amber-400 flex-shrink-0" />
                              <span className="font-mono bg-[#F5F7FA] px-2 py-0.5 rounded border border-[#E6E9F0]">
                                {item}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>

                    {control.traceability && (
                      <div className="border-t border-[#E6E9F0] pt-4">
                        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
                          <div>
                            <p className="text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">Control Drilldown</p>
                            <p className="mt-0.5 text-[10px] text-[#6B7488]">
                              {control.traceability.evidence_total} evidence records - {control.traceability.finding_total} findings - {control.traceability.audit_event_total} audit events
                            </p>
                          </div>
                          <div className="flex flex-wrap gap-2">
                            <a
                              href={control.traceability.links.evidence_url}
                              className="inline-flex items-center gap-1 rounded-lg border border-[#E6E9F0] px-2.5 py-1.5 text-[10px] font-bold text-[#475069] hover:bg-[#F5F7FA]"
                            >
                              Evidence
                              <ExternalLink className="h-3 w-3" />
                            </a>
                            <a
                              href={control.traceability.links.findings_url}
                              className="inline-flex items-center gap-1 rounded-lg border border-[#E6E9F0] px-2.5 py-1.5 text-[10px] font-bold text-[#475069] hover:bg-[#F5F7FA]"
                            >
                              Findings
                              <ExternalLink className="h-3 w-3" />
                            </a>
                            <a
                              href={control.traceability.links.audit_url}
                              className="inline-flex items-center gap-1 rounded-lg border border-[#E6E9F0] px-2.5 py-1.5 text-[10px] font-bold text-[#475069] hover:bg-[#F5F7FA]"
                            >
                              Audit
                              <ExternalLink className="h-3 w-3" />
                            </a>
                          </div>
                        </div>
                        <div className="grid gap-3 lg:grid-cols-3">
                          <TraceList title="Evidence" items={control.traceability.evidence} empty="No evidence records yet" />
                          <TraceList title="Findings" items={control.traceability.findings} empty="No findings yet" />
                          <TraceList title="Audit Events" items={control.traceability.audit_events} empty="No audit events yet" />
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="space-y-6">
          <div className="rounded-[20px] border border-[#E6E9F0] bg-white p-5 shadow-xl space-y-4">
            <h3 className="text-xs font-bold uppercase tracking-wider text-[#6B7488] flex items-center gap-1.5">
              <FileCheck className="w-4 h-4 text-indigo-400" />
              Live Score Inputs
            </h3>
            <div className="space-y-3 text-xs">
              {[
                ["Evidence Records", activeScore?.metrics.evidence_count],
                ["Audit Events", activeScore?.metrics.audit_event_count],
                ["Hash-Chained Events", activeScore?.metrics.audit_hash_count],
                ["Redaction Records", activeScore?.metrics.redaction_count],
                ["Open Findings", activeScore?.metrics.open_findings],
                ["Critical Findings", activeScore?.metrics.critical_findings],
              ].map(([label, value]) => (
                <div key={label} className="flex justify-between py-1.5 border-b border-[#E6E9F0] last:border-b-0">
                  <span className="text-[#6B7488]">{label}</span>
                  <span className="font-bold text-[#0E1726] font-mono">{loading ? "-" : value ?? 0}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-[20px] border border-[#E6E9F0] bg-white p-5 shadow-xl space-y-4">
            <h3 className="text-xs font-bold uppercase tracking-wider text-[#6B7488]">30-Day Score History</h3>
            <div className="space-y-2">
              {history.length === 0 ? (
                <div className="text-xs text-[#6B7488]">No score snapshots yet.</div>
              ) : (
                history.map((item) => (
                  <div key={`${item.framework}-${item.snapshot_date}`} className="rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] p-3">
                    <div className="flex justify-between text-xs">
                      <span className="text-[#6B7488]">{item.snapshot_date}</span>
                      <span className="font-bold text-[#0E1726]">{item.overall_score}%</span>
                    </div>
                    <div className="mt-2 h-1.5 rounded-full bg-[#F5F7FA] overflow-hidden">
                      <div className="h-full rounded-full bg-indigo-500" style={{ width: `${item.overall_score}%` }} />
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="rounded-[20px] border border-[#E6E9F0] bg-white p-5 shadow-xl space-y-4 relative overflow-hidden">
            <h3 className="text-xs font-bold uppercase tracking-wider text-[#6B7488]">Auditor Export</h3>
            <p className="text-xs text-[#6B7488] leading-normal">
              Export a signed audit artifact filtered to the selected framework. Verification is available in Audit Explorer.
            </p>

            <button
              onClick={handleSignedExport}
              disabled={exporting || loading}
              className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs shadow-lg transition active:scale-[0.98] disabled:opacity-50"
            >
              <Download className="w-4 h-4" />
              {exporting ? "Signing Export..." : `Export ${activeFramework} Audit`}
            </button>

            {exportMessage && (
              <div className="p-3 rounded-lg bg-[#F5F7FA]/60 border border-[#E6E9F0] text-[#475069] text-[10px] leading-relaxed">
                {exportMessage}
              </div>
            )}
          </div>

          {canManageShares && <div className="rounded-[20px] border border-[#E6E9F0] bg-white p-5 shadow-xl space-y-4 relative overflow-hidden">
            <div className="flex items-start justify-between gap-3">
              <div>
                <h3 className="text-xs font-bold uppercase tracking-wider text-[#6B7488] flex items-center gap-1.5">
                  <Link2 className="w-4 h-4 text-sky-300" />
                  Trust Center Share
                </h3>
                <p className="mt-2 text-xs text-[#6B7488] leading-normal">
                  Create a scoped auditor page with live scores, signed export downloads, and a verifier guide.
                </p>
              </div>
              <button
                onClick={fetchTrustShares}
                className="p-1.5 rounded-lg border border-[#E6E9F0] text-[#6B7488] hover:text-[#0E1726] hover:bg-[#F5F7FA]"
                title="Refresh Trust Center shares"
              >
                <RefreshCw className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="space-y-3">
              <label className="block text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">
                Review Label
                <input
                  value={shareForm.label}
                  onChange={(event) => setShareForm((current) => ({ ...current, label: event.target.value }))}
                  className="mt-1 w-full rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] px-3 py-2 text-xs normal-case tracking-normal text-[#0E1726] outline-none focus:border-indigo-500"
                />
              </label>
              <label className="block text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">
                Auditor Email
                <input
                  type="email"
                  required
                  value={shareForm.auditorEmail}
                  placeholder="auditor@example.com"
                  onChange={(event) => setShareForm((current) => ({ ...current, auditorEmail: event.target.value }))}
                  className="mt-1 w-full rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] px-3 py-2 text-xs normal-case tracking-normal text-[#0E1726] outline-none focus:border-indigo-500"
                />
              </label>
              <label className="block text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">
                Expires In Days
                <input
                  type="number"
                  min={1}
                  max={90}
                  value={shareForm.expiresInDays}
                  onChange={(event) => {
                    const value = Math.max(1, Math.min(90, Number(event.target.value) || 30));
                    setShareForm((current) => ({ ...current, expiresInDays: value }));
                  }}
                  className="mt-1 w-full rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] px-3 py-2 text-xs normal-case tracking-normal text-[#0E1726] outline-none focus:border-indigo-500"
                />
              </label>
              <div>
                <div className="text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">Frameworks</div>
                <div className="mt-2 grid grid-cols-3 gap-2">
                  {(Object.keys(frameworkMeta) as FrameworkId[]).map((framework) => (
                    <button
                      key={framework}
                      type="button"
                      onClick={() => toggleShareFramework(framework)}
                      className={`rounded-lg border px-2 py-2 text-[10px] font-bold transition ${
                        shareForm.frameworks.includes(framework)
                          ? "border-indigo-300 bg-indigo-50 text-indigo-700"
                          : "border-[#E6E9F0] bg-[#F5F7FA] text-[#6B7488] hover:text-[#0E1726]"
                      }`}
                    >
                      {framework}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            <button
              onClick={handleCreateTrustShare}
              disabled={shareBusy || !shareForm.auditorEmail}
              className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white font-bold text-xs shadow-lg transition active:scale-[0.98] disabled:bg-[#EEF1F6] disabled:text-[#8A94A6]"
            >
              <Link2 className="w-4 h-4" />
              {shareBusy ? "Creating Link..." : "Create Auditor Link"}
            </button>

            {createdShare && (
              <div className="space-y-2 rounded-xl border border-emerald-500/20 bg-emerald-500/10 p-3">
                <div className="text-[10px] font-bold uppercase tracking-wider text-emerald-200">One-time auditor URL</div>
                <div className="break-all rounded-lg border border-emerald-500/20 bg-[#F5F7FA] p-2 font-mono text-[10px] text-emerald-100">
                  {createdShare.url}
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    onClick={() => copyTrustCenterText("trust-url", createdShare.url)}
                    className="flex items-center justify-center gap-1.5 rounded-lg border border-emerald-500/30 px-3 py-2 text-[10px] font-bold text-emerald-100 hover:bg-emerald-500/10"
                  >
                    <Clipboard className="w-3.5 h-3.5" />
                    {copied === "trust-url" ? "Copied" : "Copy URL"}
                  </button>
                  <a
                    href={createdShare.url}
                    target="_blank"
                    rel="noreferrer"
                    className="flex items-center justify-center gap-1.5 rounded-lg border border-emerald-500/30 px-3 py-2 text-[10px] font-bold text-emerald-100 hover:bg-emerald-500/10"
                  >
                    <ExternalLink className="w-3.5 h-3.5" />
                    Open
                  </a>
                </div>
              </div>
            )}

            {shareMessage && (
              <div className="p-3 rounded-lg bg-[#F5F7FA]/60 border border-[#E6E9F0] text-[#475069] text-[10px] leading-relaxed">
                {shareMessage}
              </div>
            )}

            <div className="space-y-2">
              <div className="text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">Recent Shares</div>
              {trustShares.length === 0 ? (
                <div className="rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] p-3 text-xs text-[#6B7488]">No auditor links yet.</div>
              ) : (
                trustShares.slice(0, 5).map((share) => (
                  <div key={share.id} className="rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] p-3 text-xs">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="truncate font-bold text-[#0E1726]">{share.label}</div>
                        <div className="mt-1 text-[10px] text-[#6B7488]">
                          {share.status.toUpperCase()} - {share.frameworks.join(", ")} - {share.access_count} views
                        </div>
                        <div className="mt-1 text-[10px] text-[#6B7488]">
                          Expires {new Date(share.expires_at).toLocaleDateString()} - token {share.token_prefix}
                        </div>
                      </div>
                      {share.status === "active" && (
                        <button
                          onClick={() => handleRevokeTrustShare(share.id)}
                          disabled={shareBusy}
                          className="rounded-md border border-red-500/30 px-2 py-1 text-[10px] font-bold text-red-200 hover:bg-red-500/10 disabled:opacity-50"
                        >
                          Revoke
                        </button>
                      )}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>}
        </div>
      </div>
    </div>
  );
}
