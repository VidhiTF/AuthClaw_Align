"use client";

import { Check, Clock3, Copy, Loader2, MailWarning, RefreshCw, Send, ShieldCheck, X, type LucideIcon } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { fetchJson, jsonRequest } from "@/lib/client-fetch";
import { getErrorMessage } from "@/lib/errors";
import { formatDateTime } from "@/lib/ui-format";

type AccessRequestStatus = "PENDING" | "APPROVED" | "REJECTED" | "INVITED";
type AccessRequestKind = "DEMO" | "EARLY_ACCESS";

type AccessRequestHistory = {
  id: string;
  event_type: string;
  old_status?: string | null;
  new_status?: string | null;
  created_at: string;
  metadata?: Record<string, string | number | boolean | null | undefined>;
};

type AccessRequest = {
  reference: string;
  name: string;
  business_email: string;
  company: string;
  role: string;
  use_case: string;
  requested_access: AccessRequestKind;
  source_page: string;
  status: AccessRequestStatus;
  created_at: string;
  updated_at: string;
  history: AccessRequestHistory[];
};

const statusStyles: Record<AccessRequestStatus, string> = {
  PENDING: "border-amber-200 bg-amber-50 text-amber-800",
  APPROVED: "border-emerald-200 bg-emerald-50 text-emerald-800",
  REJECTED: "border-red-200 bg-red-50 text-red-700",
  INVITED: "border-blue-200 bg-blue-50 text-blue-700",
};

const decisionConfig: Record<AccessRequestStatus, { label: string; icon: LucideIcon; className: string } | null> = {
  PENDING: null,
  APPROVED: {
    label: "Approve",
    icon: Check,
    className: "border-emerald-200 bg-white text-emerald-700 hover:bg-emerald-50",
  },
  REJECTED: {
    label: "Reject",
    icon: X,
    className: "border-red-200 bg-white text-red-700 hover:bg-red-50",
  },
  INVITED: {
    label: "Mark invited",
    icon: Send,
    className: "border-[#6D28D9] bg-[#6D28D9] text-white hover:bg-[#7C3AED]",
  },
};

export default function AccessRequestsClient() {
  const [requests, setRequests] = useState<AccessRequest[]>([]);
  const [statusFilter, setStatusFilter] = useState<AccessRequestStatus | "ALL">("PENDING");
  const [accessFilter, setAccessFilter] = useState<AccessRequestKind | "ALL">("ALL");
  const [loading, setLoading] = useState(true);
  const [busyReference, setBusyReference] = useState<string | null>(null);
  const [copiedHistoryId, setCopiedHistoryId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadRequests = useCallback(async (showLoader = false) => {
    if (showLoader) setLoading(true);
    try {
      const params = new URLSearchParams({
        status_filter: statusFilter,
        requested_access: accessFilter,
      });
      const data = await fetchJson<AccessRequest[]>(`/api/access-requests?${params.toString()}`, {
        fallback: "Failed to load access requests",
      });
      setRequests(data || []);
      setError(null);
    } catch (requestError: unknown) {
      setError(getErrorMessage(requestError, "Failed to load access requests"));
    } finally {
      setLoading(false);
    }
  }, [accessFilter, statusFilter]);

  useEffect(() => {
    const initialLoad = window.setTimeout(() => void loadRequests(true), 0);
    return () => window.clearTimeout(initialLoad);
  }, [loadRequests]);

  const pendingCount = requests.filter((request) => request.status === "PENDING").length;
  const earlyAccessCount = requests.filter((request) => request.requested_access === "EARLY_ACCESS").length;
  const demoCount = requests.filter((request) => request.requested_access === "DEMO").length;

  const visibleRequests = useMemo(() => requests, [requests]);

  const transition = async (request: AccessRequest, newStatus: AccessRequestStatus) => {
    setBusyReference(request.reference);
    setError(null);
    try {
      const response = await fetch(
        `/api/access-requests/${encodeURIComponent(request.reference)}/status`,
        jsonRequest("PATCH", { new_status: newStatus }),
      );
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.detail || body.error || "Failed to update request");
      }
      await loadRequests();
    } catch (requestError: unknown) {
      setError(getErrorMessage(requestError, "Failed to update request"));
    } finally {
      setBusyReference(null);
    }
  };

  const copyInviteLink = async (history: AccessRequestHistory) => {
    const inviteLink = history.metadata?.invite_link;
    if (typeof inviteLink !== "string" || !inviteLink) return;
    await navigator.clipboard.writeText(inviteLink);
    setCopiedHistoryId(history.id);
    window.setTimeout(() => setCopiedHistoryId((current) => (current === history.id ? null : current)), 1400);
  };

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div className="mb-2 flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-[#6D28D9]">
            <ShieldCheck className="h-4 w-4" />
            Platform-only review
          </div>
          <h1 className="text-3xl font-extrabold tracking-tight text-[#0E1726]">Developer Console</h1>
          <p className="mt-2 max-w-3xl text-sm text-[#475069]">
            Review public demo and early-access intake before inviting organizations into AuthClaw.
          </p>
        </div>
        <button
          type="button"
          onClick={() => void loadRequests(true)}
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
          <p className="text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">Early access</p>
          <p className="mt-2 text-3xl font-black text-[#0E1726]">{earlyAccessCount}</p>
        </div>
        <div className="rounded-[20px] border border-[#E6E9F0] bg-white p-5 shadow-[0_1px_2px_rgba(11,31,63,.05)]">
          <p className="text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">Demo</p>
          <p className="mt-2 text-3xl font-black text-[#0E1726]">{demoCount}</p>
        </div>
      </section>

      <section className="overflow-hidden rounded-[20px] border border-[#E6E9F0] bg-white shadow-[0_1px_2px_rgba(11,31,63,.05),0_12px_30px_-12px_rgba(11,31,63,.18)]">
        <div className="flex flex-col gap-3 border-b border-[#E6E9F0] px-5 py-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <h2 className="text-sm font-bold text-[#0E1726]">Access request queue</h2>
            <p className="mt-1 text-xs text-[#6B7488]">Status changes are recorded in access request history.</p>
          </div>
          <div className="flex flex-wrap gap-2">
            {(["PENDING", "APPROVED", "REJECTED", "INVITED", "ALL"] as const).map((status) => (
              <button
                key={status}
                type="button"
                onClick={() => setStatusFilter(status)}
                className={`rounded-full border px-3 py-1.5 text-[10px] font-bold tracking-wide transition ${
                  statusFilter === status
                    ? "border-[#6D28D9] bg-[#F1ECFE] text-[#6D28D9]"
                    : "border-[#E6E9F0] bg-white text-[#6B7488] hover:border-[#A78BFA]"
                }`}
              >
                {status}
              </button>
            ))}
            {(["EARLY_ACCESS", "DEMO", "ALL"] as const).map((kind) => (
              <button
                key={kind}
                type="button"
                onClick={() => setAccessFilter(kind)}
                className={`rounded-full border px-3 py-1.5 text-[10px] font-bold tracking-wide transition ${
                  accessFilter === kind
                    ? "border-[#0F766E] bg-teal-50 text-[#0F766E]"
                    : "border-[#E6E9F0] bg-white text-[#6B7488] hover:border-[#5EEAD4]"
                }`}
              >
                {kind.replace("_", " ")}
              </button>
            ))}
          </div>
        </div>

        {error && <div className="border-b border-red-200 bg-red-50 px-5 py-3 text-xs text-red-700">{error}</div>}

        {loading ? (
          <div className="flex items-center justify-center gap-2 px-5 py-16 text-sm text-[#6B7488]">
            <Loader2 className="h-4 w-4 animate-spin" /> Loading access requests...
          </div>
        ) : visibleRequests.length === 0 ? (
          <div className="px-5 py-16 text-center">
            <Clock3 className="mx-auto h-8 w-8 text-[#A8B0C0]" />
            <p className="mt-3 text-sm font-semibold text-[#475069]">No matching access requests</p>
            <p className="mt-1 text-xs text-[#6B7488]">New public intake submissions appear here after form submission.</p>
          </div>
        ) : (
          <div className="divide-y divide-[#E6E9F0]">
            {visibleRequests.map((request) => (
              <article key={request.reference} className="px-5 py-5">
                <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`rounded-full border px-2.5 py-1 text-[10px] font-bold ${statusStyles[request.status]}`}>
                        {request.status}
                      </span>
                      <span className="rounded-full border border-[#D5F3EF] bg-teal-50 px-2.5 py-1 text-[10px] font-bold text-[#0F766E]">
                        {request.requested_access.replace("_", " ")}
                      </span>
                      <span className="text-xs font-semibold text-[#0E1726]">{request.reference}</span>
                    </div>
                    <h3 className="mt-3 text-base font-bold text-[#0E1726]">{request.company}</h3>
                    <p className="mt-1 text-sm text-[#475069]">
                      {request.name} · {request.role} · {request.business_email}
                    </p>
                    <p className="mt-3 max-w-4xl whitespace-pre-wrap text-sm leading-6 text-[#475069]">{request.use_case}</p>
                    <p className="mt-3 font-mono text-[10px] text-[#6B7488]">
                      {request.source_page} · created {formatDateTime(request.created_at)} · updated {formatDateTime(request.updated_at)}
                    </p>
                  </div>
                  {(request.status === "APPROVED" || request.status === "INVITED") && (
                    <button type="button" onClick={() => void transition(request, request.status)}
                      disabled={busyReference === request.reference}
                      className="inline-flex shrink-0 items-center gap-2 rounded-lg border border-[#6D28D9] bg-[#6D28D9] px-3 py-2 text-xs font-semibold text-white disabled:opacity-50">
                      <RefreshCw className={`h-4 w-4 ${busyReference === request.reference ? "animate-spin" : ""}`} />
                      {busyReference === request.reference ? "Resending..." : "Resend invitation"}
                    </button>
                  )}
                  {request.status === "PENDING" && (
                    <div className="flex shrink-0 flex-wrap gap-2">
                      {(["REJECTED", "APPROVED", "INVITED"] as const).map((decision) => {
                        const config = decisionConfig[decision];
                        if (!config) return null;
                        const Icon = config.icon;
                        return (
                          <button
                            key={decision}
                            type="button"
                            onClick={() => void transition(request, decision)}
                            disabled={busyReference === request.reference}
                            className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-2 text-xs font-semibold transition disabled:opacity-50 ${config.className}`}
                          >
                            {busyReference === request.reference ? <Loader2 className="h-4 w-4 animate-spin" /> : <Icon className="h-4 w-4" />}
                            {config.label}
                          </button>
                        );
                      })}
                    </div>
                  )}
                </div>
                <div className="mt-5 border-t border-[#E6E9F0] pt-4">
                  <div className="mb-3 flex items-center justify-between gap-3">
                    <h4 className="text-xs font-bold uppercase tracking-wide text-[#6B7488]">History</h4>
                    {request.history.some((entry) => entry.metadata?.invite_link) && (
                      <span className="text-[10px] font-semibold text-[#0F766E]">Manual invite fallback available</span>
                    )}
                  </div>
                  {request.history.length === 0 ? (
                    <p className="text-xs text-[#6B7488]">No history recorded yet.</p>
                  ) : (
                    <div className="space-y-3">
                      {request.history.map((entry) => {
                        const inviteLink = entry.metadata?.invite_link;
                        const delivery = entry.metadata?.delivery;
                        const deliveryError = entry.metadata?.delivery_error;
                        return (
                          <div key={entry.id} className="rounded-lg border border-[#E6E9F0] bg-[#F8FAFC] p-3">
                            <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                              <div>
                                <p className="text-xs font-bold text-[#0E1726]">
                                  {entry.event_type.replaceAll("_", " ")}
                                  {entry.new_status ? ` -> ${entry.new_status}` : ""}
                                </p>
                                <p className="mt-1 text-[10px] text-[#6B7488]">{formatDateTime(entry.created_at)}</p>
                              </div>
                              {typeof delivery === "string" && (
                                <span className={`inline-flex w-fit items-center gap-1.5 rounded-full border px-2.5 py-1 text-[10px] font-bold ${
                                  delivery === "failed"
                                    ? "border-red-200 bg-red-50 text-red-700"
                                    : "border-emerald-200 bg-emerald-50 text-emerald-800"
                                }`}>
                                  {delivery === "failed" && <MailWarning className="h-3.5 w-3.5" />}
                                  {delivery === "local_outbox" ? "Local invite ready — no email sent" : `Delivery ${delivery}`}
                                </span>
                              )}
                            </div>
                            {typeof inviteLink === "string" && inviteLink && (
                              <div className="mt-3 flex flex-col gap-2 sm:flex-row">
                                <input
                                  readOnly
                                  value={inviteLink}
                                  className="min-w-0 flex-1 rounded-lg border border-[#DDE3EF] bg-white px-3 py-2 font-mono text-[11px] text-[#475069]"
                                  aria-label="Invitation link"
                                />
                                <button
                                  type="button"
                                  onClick={() => void copyInviteLink(entry)}
                                  className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-[#DDE3EF] bg-white px-3 py-2 text-xs font-semibold text-[#475069] transition hover:border-[#A78BFA] hover:text-[#6D28D9]"
                                >
                                  <Copy className="h-4 w-4" />
                                  {copiedHistoryId === entry.id ? "Copied" : "Copy link"}
                                </button>
                              </div>
                            )}
                            {typeof entry.metadata?.dev_otp === "string" && (
                              <p className="mt-2 font-mono text-[11px] text-[#6D28D9]">Verification code: {entry.metadata.dev_otp}</p>
                            )}
                            {typeof deliveryError === "string" && deliveryError && (
                              <p className="mt-2 text-xs text-red-700">{deliveryError}</p>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              </article>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
