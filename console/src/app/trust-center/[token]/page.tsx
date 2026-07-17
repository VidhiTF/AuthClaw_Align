"use client";

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useParams } from "next/navigation";
import {
  AlertTriangle,
  CheckCircle2,
  Download,
  FileCheck,
  KeyRound,
  ShieldCheck,
  Upload,
} from "lucide-react";
import { TrustSummary } from "@/components/trust-summary";
import type { TrustSummary as TrustSummaryData } from "@/lib/trust-summary";

interface ControlScore {
  id: string;
  name: string;
  description: string;
  score: number;
  status: "compliant" | "partial" | "non_compliant";
  evidence: string[];
  gaps: string[];
}

interface FrameworkScore {
  framework: string;
  score: number;
  readiness_level: string;
  controls: ControlScore[];
  metrics: {
    evidence_count: number;
    audit_event_count: number;
    audit_hash_count: number;
    redaction_count: number;
    open_findings: number;
    critical_findings: number;
  };
}

interface TrustCenterPackage {
  tenant: { id: string; name: string; tier: string };
  share: {
    label: string;
    auditor_email: string;
    frameworks: string[];
    expires_at: string;
    status: string;
    access_count: number;
  };
  scores: {
    overall_score: number;
    readiness_level: string;
    frameworks: FrameworkScore[];
    generated_at: string;
    trust_summary?: TrustSummaryData;
  };
  signing_key: {
    algorithm: string;
    key_id: string;
    public_key: string;
  };
  verification_guide: Array<{ title: string; body: string }>;
  generated_at: string;
}

interface VerifyResult {
  verified: boolean;
  signature_valid: boolean;
  digest_valid: boolean;
  chain_valid: boolean;
  record_count: number;
  key_id: string;
  errors: string[];
  last_hash: string;
}

const statusClass = (status: string) => {
  if (status === "compliant") return "border-emerald-500/25 bg-emerald-500/10 text-emerald-200";
  if (status === "partial") return "border-amber-500/25 bg-amber-500/10 text-amber-100";
  return "border-red-500/25 bg-red-500/10 text-red-200";
};

const readinessLabel = (value: string) => value.replaceAll("_", " ").toUpperCase();

export default function TrustCenterPage() {
  const params = useParams<{ token: string }>();
  const token = params.token;
  const [data, setData] = useState<TrustCenterPackage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedFramework, setSelectedFramework] = useState("");
  const [exporting, setExporting] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<VerifyResult | null>(null);
  const [accessToken, setAccessToken] = useState("");
  const [otpSentTo, setOtpSentTo] = useState("");
  const [otp, setOtp] = useState("");
  const [accessBusy, setAccessBusy] = useState(false);
  const fileRef = useRef<HTMLInputElement | null>(null);

  const loadPackage = useCallback(async (verifiedAccess: string) => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`/api/trust-center/public/${encodeURIComponent(token)}`, {
        headers: { "X-Trust-Center-Access": verifiedAccess },
      });
      const payload = await res.json();
      if (!res.ok) throw new Error(payload.detail || payload.error || "Trust Center link is unavailable");
      setData(payload);
      setSelectedFramework(payload.share?.frameworks?.[0] || "");
    } catch (err: unknown) {
      sessionStorage.removeItem(`trust-center:${token}`);
      setAccessToken("");
      setData(null);
      setError(err instanceof Error ? err.message : "Trust Center link is unavailable");
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    if (!token) return;
    const savedAccess = sessionStorage.getItem(`trust-center:${token}`) || "";
    if (savedAccess) {
      setAccessToken(savedAccess);
      void loadPackage(savedAccess);
    } else {
      setLoading(false);
    }
  }, [loadPackage, token]);

  const requestAccess = async () => {
    setAccessBusy(true);
    setError(null);
    try {
      const res = await fetch(`/api/trust-center/public/${encodeURIComponent(token)}/request-access`, { method: "POST" });
      const payload = await res.json();
      if (!res.ok) throw new Error(payload.detail || payload.error || "Could not send verification code");
      setOtpSentTo(payload.email || "the configured auditor email");
      if (payload.dev_otp) setOtp(payload.dev_otp);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Could not send verification code");
    } finally {
      setAccessBusy(false);
    }
  };

  const verifyAccess = async () => {
    setAccessBusy(true);
    setError(null);
    try {
      const res = await fetch(`/api/trust-center/public/${encodeURIComponent(token)}/verify-access`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ otp }),
      });
      const payload = await res.json();
      if (!res.ok) throw new Error(payload.detail || payload.error || "Could not verify auditor email");
      sessionStorage.setItem(`trust-center:${token}`, payload.access_token);
      setAccessToken(payload.access_token);
      await loadPackage(payload.access_token);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Could not verify auditor email");
    } finally {
      setAccessBusy(false);
    }
  };

  const activeFramework = useMemo(
    () => data?.scores.frameworks.find((framework) => framework.framework === selectedFramework) || data?.scores.frameworks[0],
    [data, selectedFramework],
  );

  const downloadSignedExport = async (framework?: string) => {
    setExporting(true);
    setError(null);
    try {
      const query = framework ? `?framework=${encodeURIComponent(framework)}` : "";
      const res = await fetch(`/api/trust-center/public/${encodeURIComponent(token)}/signed-export${query}`, {
        headers: { "X-Trust-Center-Access": accessToken },
      });
      const artifact = await res.json();
      if (!res.ok) throw new Error(artifact.detail || artifact.error || "Signed export failed");
      const dataStr = "data:application/json;charset=utf-8," + encodeURIComponent(JSON.stringify(artifact, null, 2));
      const anchor = document.createElement("a");
      anchor.href = dataStr;
      anchor.download = `authclaw_${framework || "full"}_signed_export_${artifact.payload?.export_id || Date.now()}.json`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Signed export failed");
    } finally {
      setExporting(false);
    }
  };

  const verifyFile = async (file: File) => {
    setVerifying(true);
    setVerifyResult(null);
    setError(null);
    try {
      const artifact = JSON.parse(await file.text());
      const res = await fetch("/api/trust-center/public/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ artifact }),
      });
      const payload = await res.json();
      if (!res.ok) throw new Error(payload.detail || payload.error || "Verification failed");
      setVerifyResult(payload);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Verification failed");
    } finally {
      setVerifying(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  };

  if (loading) {
    return (
      <main className="min-h-screen bg-[#050508] text-white flex items-center justify-center">
        <div className="h-8 w-8 rounded-full border-2 border-indigo-400 border-t-transparent animate-spin" />
      </main>
    );
  }

  if (!data) {
    return (
      <main className="min-h-screen bg-[#050508] text-white flex items-center justify-center p-6">
        <div className="w-full max-w-md rounded-2xl border border-slate-800 bg-[#09090d] p-6">
          <KeyRound className="mb-3 h-10 w-10 text-indigo-300" />
          <h1 className="text-xl font-bold">Verify auditor email</h1>
          <p className="mt-2 text-sm text-slate-400">
            This Trust Center link is email-bound. Request the six-digit code sent to its configured auditor.
          </p>
          {error && <div className="mt-4 rounded-lg border border-red-500/20 bg-red-500/10 p-3 text-xs text-red-100">{error}</div>}
          {otpSentTo ? (
            <div className="mt-5 space-y-3">
              <p className="text-xs text-slate-400">Code sent to {otpSentTo}</p>
              <input
                value={otp}
                onChange={(event) => setOtp(event.target.value.replace(/\D/g, "").slice(0, 6))}
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder="000000"
                className="w-full rounded-lg border border-slate-700 bg-[#050508] px-3 py-2 text-center font-mono text-lg tracking-[0.4em] outline-none focus:border-indigo-500"
              />
              <button
                onClick={() => void verifyAccess()}
                disabled={accessBusy || otp.length !== 6}
                className="w-full rounded-lg bg-indigo-600 px-4 py-2 text-sm font-bold hover:bg-indigo-500 disabled:opacity-50"
              >
                {accessBusy ? "Verifying..." : "Verify and open"}
              </button>
              <button
                onClick={() => void requestAccess()}
                disabled={accessBusy}
                className="w-full text-xs text-slate-400 hover:text-white disabled:opacity-50"
              >
                Send another code
              </button>
            </div>
          ) : (
            <button
              onClick={() => void requestAccess()}
              disabled={accessBusy}
              className="mt-5 w-full rounded-lg bg-indigo-600 px-4 py-2 text-sm font-bold hover:bg-indigo-500 disabled:opacity-50"
            >
              {accessBusy ? "Sending..." : "Send verification code"}
            </button>
          )}
        </div>
      </main>
    );
  }

  if (!data) return null;

  return (
    <main className="min-h-screen bg-[#050508] text-slate-100">
      <div className="mx-auto max-w-7xl px-6 py-8 space-y-8">
        <header className="flex flex-col gap-5 border-b border-slate-800 pb-6 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-indigo-500/25 bg-indigo-500/10 px-3 py-1 text-[10px] font-bold uppercase tracking-wider text-indigo-200">
              <ShieldCheck className="h-3.5 w-3.5" />
              AuthClaw Auditor Trust Center
            </div>
            <h1 className="text-3xl font-black tracking-tight text-white">{data.tenant.name}</h1>
            <p className="mt-2 max-w-3xl text-sm text-slate-400">
              {data.share.label} - Expires {new Date(data.share.expires_at).toLocaleString()} - Generated {new Date(data.generated_at).toLocaleString()}
            </p>
          </div>
          <div className="rounded-2xl border border-slate-800 bg-[#09090d] p-5 min-w-[220px]">
            <div className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Overall Readiness</div>
            <div className="mt-2 text-4xl font-black text-white">{data.scores.overall_score}%</div>
            <div className="mt-1 text-xs font-semibold text-indigo-200">{readinessLabel(data.scores.readiness_level)}</div>
          </div>
        </header>

        {error && (
          <div className="rounded-xl border border-amber-500/20 bg-amber-500/10 p-4 text-sm text-amber-100">
            {error}
          </div>
        )}

        <section className="grid gap-4 md:grid-cols-3">
          {data.scores.frameworks.map((framework) => (
            <button
              key={framework.framework}
              onClick={() => setSelectedFramework(framework.framework)}
              className={`text-left rounded-2xl border p-5 transition ${
                activeFramework?.framework === framework.framework
                  ? "border-indigo-500/50 bg-indigo-950/20"
                  : "border-slate-800 bg-[#09090d] hover:border-slate-700"
              }`}
            >
              <div className="flex items-start justify-between">
                <div>
                  <div className="text-sm font-bold text-white">{framework.framework}</div>
                  <div className="mt-1 text-[10px] font-semibold uppercase text-slate-500">{readinessLabel(framework.readiness_level)}</div>
                </div>
                <div className="text-2xl font-black text-indigo-200">{framework.score}%</div>
              </div>
              <div className="mt-4 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                <div className="h-full rounded-full bg-indigo-500" style={{ width: `${framework.score}%` }} />
              </div>
              <div className="mt-3 text-xs text-slate-500">
                {framework.metrics.evidence_count} evidence - {framework.metrics.audit_event_count} audit events - {framework.metrics.open_findings} open findings
              </div>
            </button>
          ))}
        </section>

        <TrustSummary summary={data.scores.trust_summary} dark />

        {activeFramework && (
          <section className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_360px]">
            <div className="rounded-2xl border border-slate-800 bg-[#09090d] overflow-hidden">
              <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
                <h2 className="text-sm font-bold uppercase tracking-wider text-slate-200">{activeFramework.framework} Control Evidence</h2>
                <span className="text-[10px] font-bold text-slate-500">{activeFramework.controls.length} controls</span>
              </div>
              <div className="divide-y divide-slate-800/70">
                {activeFramework.controls.map((control) => (
                  <div key={control.id} className="p-5">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div className="flex items-center gap-2">
                        <span className="rounded border border-indigo-500/20 bg-indigo-500/10 px-2 py-0.5 font-mono text-xs font-bold text-indigo-200">{control.id}</span>
                        <h3 className="text-sm font-bold text-white">{control.name}</h3>
                      </div>
                      <span className={`rounded-full border px-2.5 py-1 text-[10px] font-bold uppercase ${statusClass(control.status)}`}>
                        {control.status.replace("_", " ")} - {control.score}%
                      </span>
                    </div>
                    <p className="mt-2 text-xs leading-relaxed text-slate-400">{control.description}</p>
                    <div className="mt-4 grid gap-3 md:grid-cols-2">
                      <div>
                        <div className="mb-2 text-[10px] font-bold uppercase tracking-wider text-slate-500">Evidence</div>
                        {(control.evidence.length ? control.evidence : ["No evidence signal yet"]).map((item) => (
                          <div key={item} className="mb-1 rounded-lg border border-slate-800 bg-[#07070a] px-3 py-2 text-xs text-slate-300">
                            {item}
                          </div>
                        ))}
                      </div>
                      <div>
                        <div className="mb-2 text-[10px] font-bold uppercase tracking-wider text-slate-500">Gaps</div>
                        {(control.gaps.length ? control.gaps : ["No active gap"]).map((item) => (
                          <div key={item} className="mb-1 rounded-lg border border-slate-800 bg-[#07070a] px-3 py-2 text-xs text-slate-400">
                            {item}
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <aside className="space-y-6">
              <div className="rounded-2xl border border-slate-800 bg-[#09090d] p-5">
                <h2 className="flex items-center gap-2 text-sm font-bold text-white">
                  <Download className="h-4 w-4 text-indigo-300" />
                  Signed Evidence Export
                </h2>
                <p className="mt-2 text-xs leading-relaxed text-slate-500">
                  Download an Ed25519-signed audit export. The verifier checks the signature, payload digest, record counts, and every hash-chain link.
                </p>
                <div className="mt-4 grid gap-2">
                  <button
                    onClick={() => downloadSignedExport(activeFramework.framework)}
                    disabled={exporting}
                    className="rounded-lg bg-indigo-600 px-4 py-2 text-xs font-bold text-white hover:bg-indigo-500 disabled:opacity-50"
                  >
                    {exporting ? "Signing..." : `Download ${activeFramework.framework} Export`}
                  </button>
                  {["SOC2", "GDPR", "HIPAA"].every((framework) => data.share.frameworks.includes(framework)) && (
                    <button
                      onClick={() => downloadSignedExport()}
                      disabled={exporting}
                      className="rounded-lg border border-slate-700 px-4 py-2 text-xs font-bold text-slate-200 hover:bg-slate-800 disabled:opacity-50"
                    >
                      Download Full Export
                    </button>
                  )}
                </div>
              </div>

              <div className="rounded-2xl border border-slate-800 bg-[#09090d] p-5">
                <h2 className="flex items-center gap-2 text-sm font-bold text-white">
                  <Upload className="h-4 w-4 text-sky-300" />
                  Verify Export
                </h2>
                <p className="mt-2 text-xs leading-relaxed text-slate-500">
                  Upload a signed JSON artifact to verify it against the embedded public key and hash-chain anchors.
                </p>
                <input
                  ref={fileRef}
                  type="file"
                  accept="application/json,.json"
                  className="hidden"
                  onChange={(event) => {
                    const file = event.target.files?.[0];
                    if (file) void verifyFile(file);
                  }}
                />
                <button
                  onClick={() => fileRef.current?.click()}
                  disabled={verifying}
                  className="mt-4 w-full rounded-lg border border-slate-700 px-4 py-2 text-xs font-bold text-slate-200 hover:bg-slate-800 disabled:opacity-50"
                >
                  {verifying ? "Verifying..." : "Upload and Verify"}
                </button>
                {verifyResult && (
                  <div className={`mt-4 rounded-xl border p-3 text-xs ${
                    verifyResult.verified ? "border-emerald-500/20 bg-emerald-500/10 text-emerald-100" : "border-red-500/20 bg-red-500/10 text-red-100"
                  }`}>
                    <div className="flex items-center gap-2 font-bold">
                      {verifyResult.verified ? <CheckCircle2 className="h-4 w-4" /> : <AlertTriangle className="h-4 w-4" />}
                      {verifyResult.verified ? "Verified" : "Verification failed"}
                    </div>
                    <div className="mt-1 opacity-80">
                      {verifyResult.record_count} records - signature {verifyResult.signature_valid ? "valid" : "invalid"} - chain {verifyResult.chain_valid ? "valid" : "invalid"}
                    </div>
                    {verifyResult.errors.length > 0 && <div className="mt-2 font-mono text-[10px]">{verifyResult.errors[0]}</div>}
                  </div>
                )}
              </div>

              <div className="rounded-2xl border border-slate-800 bg-[#09090d] p-5">
                <h2 className="flex items-center gap-2 text-sm font-bold text-white">
                  <KeyRound className="h-4 w-4 text-amber-200" />
                  Verification Guide
                </h2>
                <div className="mt-4 space-y-3">
                  {data.verification_guide.map((step) => (
                    <div key={step.title} className="rounded-xl border border-slate-800 bg-[#07070a] p-3">
                      <div className="flex items-center gap-2 text-xs font-bold text-slate-200">
                        <FileCheck className="h-3.5 w-3.5 text-indigo-300" />
                        {step.title}
                      </div>
                      <p className="mt-1 break-words text-[11px] leading-relaxed text-slate-500">{step.body}</p>
                    </div>
                  ))}
                </div>
              </div>
            </aside>
          </section>
        )}
      </div>
    </main>
  );
}
