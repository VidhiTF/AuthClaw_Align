"use client";

import { Check, Clock3, Loader2, RefreshCw, ShieldCheck, X } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import MfaChallengeModal from "@/components/mfa-challenge-modal";
import { fetchJson } from "@/lib/client-fetch";
import { getErrorMessage } from "@/lib/errors";

type ApprovalStatus = "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED";

type GatewayApproval = {
  id: string;
  action_id: string;
  action_type: string;
  action_description: string;
  action_payload: Record<string, unknown>;
  status: ApprovalStatus;
  requester_id: string;
  approver_id?: string | null;
  expires_at: string;
  created_at: string;
};

type Session = {
  role?: string;
};

const statusStyles: Record<ApprovalStatus, string> = {
  PENDING: "border-amber-200 bg-amber-50 text-amber-800",
  APPROVED: "border-emerald-200 bg-emerald-50 text-emerald-800",
  REJECTED: "border-red-200 bg-red-50 text-red-700",
  EXPIRED: "border-slate-200 bg-slate-50 text-slate-600",
};

function payloadText(payload: Record<string, unknown>, key: string) {
  const value = payload[key];
  return typeof value === "string" && value ? value : null;
}

export default function ApprovalsPage() {
  const [approvals, setApprovals] = useState<GatewayApproval[]>([]);
  const [role, setRole] = useState("viewer");
  const [filter, setFilter] = useState<"ALL" | ApprovalStatus>("PENDING");
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [mfaTarget, setMfaTarget] = useState<GatewayApproval | null>(null);
  const [mfaCode, setMfaCode] = useState("");
  const [mfaError, setMfaError] = useState<string | null>(null);

  const canDecide = role === "owner" || role === "admin";

  const loadApprovals = useCallback(async (showLoader = false) => {
    if (showLoader) setLoading(true);
    try {
      const [items, session] = await Promise.all([
        fetchJson<GatewayApproval[]>("/api/approvals", { fallback: "Failed to load approvals" }),
        fetchJson<Session>("/api/auth/session", { fallback: "Failed to load session" }),
      ]);
      if (items) setApprovals(items);
      if (session?.role) setRole(session.role.toLowerCase());
      setError(null);
    } catch (requestError: unknown) {
      setError(getErrorMessage(requestError, "Failed to load approvals"));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const initialLoad = window.setTimeout(() => void loadApprovals(true), 0);
    return () => window.clearTimeout(initialLoad);
  }, [loadApprovals]);

  const visibleApprovals = useMemo(
    () => approvals.filter((approval) => filter === "ALL" || approval.status === filter),
    [approvals, filter],
  );

  const pendingCount = approvals.filter((approval) => approval.status === "PENDING").length;

  const decide = async (approval: GatewayApproval, decision: "approve" | "reject", totpCode?: string) => {
    setBusyId(approval.id);
    setError(null);
    try {
      const response = await fetch(`/api/approvals/${approval.id}/${decision}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(decision === "approve" && totpCode ? { totp_code: totpCode } : {}),
      });
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.detail || body.error || `Failed to ${decision} approval`);
      }
      await loadApprovals();
    } finally {
      setBusyId(null);
    }
  };

  const submitApproval = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!mfaTarget) return;
    setMfaError(null);
    try {
      await decide(mfaTarget, "approve", mfaCode || undefined);
      setMfaTarget(null);
      setMfaCode("");
    } catch (requestError: unknown) {
      setMfaError(getErrorMessage(requestError, "Approval failed"));
    }
  };

  const rejectApproval = async (approval: GatewayApproval) => {
    try {
      await decide(approval, "reject");
    } catch (requestError: unknown) {
      setError(getErrorMessage(requestError, "Rejection failed"));
    }
  };

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div className="mb-2 flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-[#6D28D9]">
            <ShieldCheck className="h-4 w-4" />
            Human-in-the-loop control
          </div>
          <h1 className="text-3xl font-extrabold tracking-tight text-[#0E1726]">Approvals</h1>
          <p className="mt-2 max-w-3xl text-sm text-[#475069]">
            Review tenant-scoped gateway requests that require an explicit operator decision before provider egress.
          </p>
        </div>
        <button
          type="button"
          onClick={() => void loadApprovals(true)}
          disabled={loading}
          className="inline-flex items-center justify-center gap-2 rounded-lg border border-[#E6E9F0] bg-white px-4 py-2 text-xs font-semibold text-[#475069] transition hover:border-[#A78BFA] hover:text-[#6D28D9] disabled:opacity-50"
        >
          <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      <section className="grid gap-4 sm:grid-cols-3">
        <div className="rounded-[20px] border border-[#E6E9F0] bg-white p-5 shadow-[0_1px_2px_rgba(11,31,63,.05)]">
          <p className="text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">Pending</p>
          <p className="mt-2 text-3xl font-black text-[#0E1726]">{pendingCount}</p>
        </div>
        <div className="rounded-[20px] border border-[#E6E9F0] bg-white p-5 shadow-[0_1px_2px_rgba(11,31,63,.05)]">
          <p className="text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">Recent decisions</p>
          <p className="mt-2 text-3xl font-black text-[#0E1726]">{approvals.length - pendingCount}</p>
        </div>
        <div className="rounded-[20px] border border-[#E6E9F0] bg-white p-5 shadow-[0_1px_2px_rgba(11,31,63,.05)]">
          <p className="text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">Decision access</p>
          <p className="mt-2 text-sm font-bold capitalize text-[#0E1726]">{canDecide ? `${role} enabled` : "Read only"}</p>
        </div>
      </section>

      <section className="overflow-hidden rounded-[20px] border border-[#E6E9F0] bg-white shadow-[0_1px_2px_rgba(11,31,63,.05),0_12px_30px_-12px_rgba(11,31,63,.18)]">
        <div className="flex flex-col gap-3 border-b border-[#E6E9F0] px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="text-sm font-bold text-[#0E1726]">Gateway approval queue</h2>
            <p className="mt-1 text-xs text-[#6B7488]">Decisions are enforced and audited by the canonical control plane.</p>
          </div>
          <div className="flex flex-wrap gap-2">
            {(["PENDING", "APPROVED", "REJECTED", "EXPIRED", "ALL"] as const).map((status) => (
              <button
                key={status}
                type="button"
                onClick={() => setFilter(status)}
                className={`rounded-full border px-3 py-1.5 text-[10px] font-bold tracking-wide transition ${
                  filter === status
                    ? "border-[#6D28D9] bg-[#F1ECFE] text-[#6D28D9]"
                    : "border-[#E6E9F0] bg-white text-[#6B7488] hover:border-[#A78BFA]"
                }`}
              >
                {status}
              </button>
            ))}
          </div>
        </div>

        {error && <div className="border-b border-red-200 bg-red-50 px-5 py-3 text-xs text-red-700">{error}</div>}

        {loading ? (
          <div className="flex items-center justify-center gap-2 px-5 py-16 text-sm text-[#6B7488]">
            <Loader2 className="h-4 w-4 animate-spin" /> Loading approvals...
          </div>
        ) : visibleApprovals.length === 0 ? (
          <div className="px-5 py-16 text-center">
            <Clock3 className="mx-auto h-8 w-8 text-[#A8B0C0]" />
            <p className="mt-3 text-sm font-semibold text-[#475069]">No {filter === "ALL" ? "" : filter.toLowerCase()} approvals</p>
            <p className="mt-1 text-xs text-[#6B7488]">Requests appear here when a gateway policy requires human review.</p>
          </div>
        ) : (
          <div className="divide-y divide-[#E6E9F0]">
            {visibleApprovals.map((approval) => {
              const provider = payloadText(approval.action_payload, "provider");
              const model = payloadText(approval.action_payload, "model");
              const reason = payloadText(approval.action_payload, "reason") || approval.action_description;
              return (
                <article key={approval.id} className="flex flex-col gap-4 px-5 py-5 lg:flex-row lg:items-center lg:justify-between">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`rounded-full border px-2.5 py-1 text-[10px] font-bold ${statusStyles[approval.status]}`}>
                        {approval.status}
                      </span>
                      <span className="text-xs font-semibold text-[#0E1726]">{provider || "Gateway request"}{model ? ` / ${model}` : ""}</span>
                    </div>
                    <p className="mt-2 text-sm text-[#475069]">{reason}</p>
                    <p className="mt-2 font-mono text-[10px] text-[#6B7488]">
                      {approval.action_id} · created {new Date(approval.created_at).toLocaleString()} · expires {new Date(approval.expires_at).toLocaleString()}
                    </p>
                  </div>
                  {approval.status === "PENDING" && canDecide && (
                    <div className="flex shrink-0 gap-2">
                      <button
                        type="button"
                        onClick={() => void rejectApproval(approval)}
                        disabled={busyId === approval.id}
                        className="inline-flex items-center gap-1.5 rounded-lg border border-red-200 bg-white px-3 py-2 text-xs font-semibold text-red-700 transition hover:bg-red-50 disabled:opacity-50"
                      >
                        <X className="h-4 w-4" /> Reject
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          setMfaTarget(approval);
                          setMfaCode("");
                          setMfaError(null);
                        }}
                        disabled={busyId === approval.id}
                        className="inline-flex items-center gap-1.5 rounded-lg bg-[#6D28D9] px-3 py-2 text-xs font-semibold text-white transition hover:bg-[#7C3AED] disabled:opacity-50"
                      >
                        <Check className="h-4 w-4" /> Approve
                      </button>
                    </div>
                  )}
                </article>
              );
            })}
          </div>
        )}
      </section>

      {mfaTarget && (
        <MfaChallengeModal
          code={mfaCode}
          setCode={setMfaCode}
          busy={busyId === mfaTarget.id}
          error={mfaError}
          onClose={() => setMfaTarget(null)}
          onSubmit={submitApproval}
          description="Confirm this gateway egress decision. Enter a TOTP or backup code if MFA is enabled for your account."
          submitLabel="Approve request"
        />
      )}
    </div>
  );
}
