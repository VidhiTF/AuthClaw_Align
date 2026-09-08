"use client";

import Image from "next/image";
import React, { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  ArrowRight,
  Check,
  CheckCircle2,
  ChevronRight,
  Clipboard,
  Code2,
  Eye,
  EyeOff,
  KeyRound,
  LockKeyhole,
  Play,
  RefreshCw,
  ShieldCheck,
  Trash2,
} from "lucide-react";
import MfaChallengeModal from "@/components/mfa-challenge-modal";
import { useRuntimeConfig } from "@/lib/runtime-config";
import { fetchJson } from "@/lib/client-fetch";
import { flashCopy } from "@/lib/clipboard";
import { getErrorMessage } from "@/lib/errors";
import { isProvider, providerCatalog, type Provider } from "@/lib/providers";

const providerLogos: Record<Provider, string> = {
  openai: "/provider-logos/openai.svg",
  anthropic: "/provider-logos/anthropic.svg",
  cohere: "/provider-logos/cohere.svg",
  azure_openai: "/provider-logos/azure.svg",
  gemini: "/provider-logos/gemini.svg",
};

interface GatewayApproval {
  id: string;
  action_id: string;
  action_description: string;
  action_payload: {
    provider?: string;
    model?: string;
    rule_name?: string;
    reason?: string;
    severity?: string;
    request_id?: string;
  };
  status: string;
  expires_at: string;
  created_at: string;
}

interface ProviderCredential {
  id: string;
  provider: string;
  display_name: string;
  endpoint?: string | null;
  status: string;
  created_at: string;
  rotated_at?: string | null;
}

interface LiteHealthItem {
  key: string;
  label: string;
  ok: boolean;
  detail: string;
}

interface GatewayTestResult {
  ok: boolean;
  status: number;
  provider: Provider;
  request_id: string;
  duration_ms: number;
  path: string;
  gateway_url: string;
  content_type?: string;
  contract?: {
    readiness: string;
    last_reviewed: string;
    payload: string;
    streaming: string;
    ci_gate: string;
  };
  checks?: Array<{ label: string; ok: boolean; detail: string }>;
  response?: unknown;
  raw?: string;
  error?: string;
}

interface OnboardingConnectResult {
  tenant_id?: string;
  tenant_name: string;
  email: string;
  api_key: string;
  gateway_url: string;
  provider: string;
  model: string;
  powershell_snippet: string;
  curl_snippet: string;
}

export default function ConnectPage() {
  const runtimeConfig = useRuntimeConfig();
  const [provider, setProvider] = useState<Provider>("gemini");
  const [copied, setCopied] = useState<string | null>(null);
  const [codeTab, setCodeTab] = useState<"curl" | "python">("curl");
  const [showCredentialKey, setShowCredentialKey] = useState(false);
  const [approvals, setApprovals] = useState<GatewayApproval[]>([]);
  const [approvalError, setApprovalError] = useState<string | null>(null);
  const [approvalBusy, setApprovalBusy] = useState<string | null>(null);
  // Gateway HITL MFA modal state
  const [gatewayMfaTarget, setGatewayMfaTarget] = useState<GatewayApproval | null>(null);
  const [gatewayTotpCode, setGatewayTotpCode] = useState("");
  const [gatewayMfaError, setGatewayMfaError] = useState<string | null>(null);
  const [gatewayMfaBusy, setGatewayMfaBusy] = useState(false);
  const [credentials, setCredentials] = useState<ProviderCredential[]>([]);
  const [credentialsLoaded, setCredentialsLoaded] = useState(false);
  const [credentialProvider, setCredentialProvider] = useState<Provider>("gemini");
  const [credentialName, setCredentialName] = useState("Production provider key");
  const [credentialKey, setCredentialKey] = useState("");
  const [credentialEndpoint, setCredentialEndpoint] = useState("");
  const [credentialMessage, setCredentialMessage] = useState<string | null>(null);
  const [credentialError, setCredentialError] = useState<string | null>(null);
  const [credentialSaving, setCredentialSaving] = useState(false);
  const [healthItems, setHealthItems] = useState<LiteHealthItem[]>([]);
  const [healthReady, setHealthReady] = useState(false);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [testBusy, setTestBusy] = useState(false);
  const [testResult, setTestResult] = useState<GatewayTestResult | null>(null);
  const [testError, setTestError] = useState<string | null>(null);
  const [onboardingResult, setOnboardingResult] = useState<OnboardingConnectResult | null>(null);
  const gatewayUrl = onboardingResult?.gateway_url || runtimeConfig?.gateway_url || "";
  const selected = providerCatalog[provider];

  const selectProvider = (nextProvider: Provider) => {
    setProvider(nextProvider);
    setCredentialProvider(nextProvider);
  };

  const curlCommand = useMemo(() => {
    return `curl -X POST ${gatewayUrl}${selected.path} \\
  -H "Authorization: Bearer <AUTHCLAW_GATEWAY_KEY>" \\
  -H "${selected.header}" \\
  -H "X-Request-ID: demo-001" \\
  -H "Content-Type: application/json" \\
  -d '${selected.sampleBody.replace(/'/g, "'\\''")}'`;
  }, [gatewayUrl, selected]);

  const pythonSdkSnippet = useMemo(() => {
    const payload = selected.sampleBody
      .split("\n")
      .map((line, index) => (index === 0 ? line : `        ${line}`))
      .join("\n");

    return `from authclaw_lite import AuthClaw

client = AuthClaw(
    api_key="<AUTHCLAW_GATEWAY_KEY>",
    gateway_url="${gatewayUrl}",
)

response = client.request(
    path="${selected.path}",
    provider="${provider}",
    request_id="demo-001",
    payload=${payload},
)
print(response)`;
  }, [gatewayUrl, provider, selected]);

  const copy = async (id: string, value: string) => {
    await flashCopy(value, setCopied, id, null, 1500);
  };

  const dismissOnboardingResult = () => {
    window.sessionStorage.removeItem("authclaw_onboarding_result");
    setOnboardingResult(null);
  };

  const fetchApprovals = async () => {
    try {
      const data = await fetchJson<GatewayApproval[]>("/api/approvals", { fallback: "Failed to load approvals", preferApiError: false });
      if (!data) return;
      setApprovals(data);
      setApprovalError(null);
    } catch (error: unknown) {
      setApprovalError(getErrorMessage(error, "Failed to load approvals"));
    }
  };

  const fetchCredentials = async () => {
    try {
      const data = await fetchJson<ProviderCredential[]>("/api/provider-credentials", { fallback: "Failed to load provider credentials", preferApiError: false });
      if (!data) return;
      setCredentials(data);
      setCredentialError(null);
    } catch (error: unknown) {
      setCredentialError(getErrorMessage(error, "Failed to load provider credentials"));
    } finally {
      setCredentialsLoaded(true);
    }
  };

  const fetchHealth = async () => {
    try {
      const data = await fetchJson<{ items?: LiteHealthItem[]; ready?: boolean }>("/api/lite-health", { fallback: "Failed to load integration health", preferApiError: false });
      if (!data) return;
      setHealthItems(data.items || []);
      setHealthReady(Boolean(data.ready));
      setHealthError(null);
    } catch (error: unknown) {
      setHealthError(getErrorMessage(error, "Failed to load integration health"));
    }
  };

  useEffect(() => {
    const initialFetch = window.setTimeout(() => {
      void fetchApprovals();
      void fetchCredentials();
      void fetchHealth();
    }, 0);
    const interval = window.setInterval(fetchApprovals, 3000);
    return () => {
      window.clearTimeout(initialFetch);
      window.clearInterval(interval);
    };
  }, []);

  useEffect(() => {
    let cancelled = false;

    const loadOnboardingResult = async () => {
      const saved = window.sessionStorage.getItem("authclaw_onboarding_result");
      if (!saved) return;
      try {
        const parsed = JSON.parse(saved) as OnboardingConnectResult;
        const sessionRes = await fetch("/api/auth/session", { cache: "no-store" });
        if (!sessionRes.ok) {
          window.sessionStorage.removeItem("authclaw_onboarding_result");
          return;
        }
        const session = await sessionRes.json();
        const belongsToCurrentTenant = parsed.tenant_id && parsed.tenant_id === session.tenantId;
        const belongsToCurrentEmail = parsed.email && parsed.email === session.email;
        if (!belongsToCurrentTenant || !belongsToCurrentEmail) {
          window.sessionStorage.removeItem("authclaw_onboarding_result");
          return;
        }
        if (cancelled) return;
        setOnboardingResult(parsed);
        if (parsed.provider && isProvider(parsed.provider)) {
          setProvider(parsed.provider);
          setCredentialProvider(parsed.provider);
        }
      } catch {
        window.sessionStorage.removeItem("authclaw_onboarding_result");
      }
    };

    void loadOnboardingResult();
    return () => {
      cancelled = true;
    };
  }, []);

  const decideApproval = async (id: string, decision: "approve" | "reject", totpCode?: string) => {
    setApprovalBusy(id);
    try {
      const body = decision === "approve" && totpCode ? { totp_code: totpCode } : {};
      const res = await fetch(`/api/approvals/${id}/${decision}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.detail || data.error || `Failed to ${decision} approval`);
      }
      await fetchApprovals();
    } catch (error: unknown) {
      setApprovalError(getErrorMessage(error, `Failed to ${decision} approval`));
    } finally {
      setApprovalBusy(null);
    }
  };

  const handleGatewayApproveClick = (approval: GatewayApproval) => {
    setGatewayMfaTarget(approval);
    setGatewayTotpCode("");
    setGatewayMfaError(null);
  };

  const handleGatewayMfaSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!gatewayMfaTarget) return;
    setGatewayMfaBusy(true);
    setGatewayMfaError(null);
    try {
      await decideApproval(gatewayMfaTarget.id, "approve", gatewayTotpCode || undefined);
      setGatewayMfaTarget(null);
    } catch (error: unknown) {
      setGatewayMfaError(getErrorMessage(error, "MFA validation failed"));
    } finally {
      setGatewayMfaBusy(false);
    }
  };

  const saveCredential = async () => {
    setCredentialSaving(true);
    setCredentialError(null);
    setCredentialMessage(null);
    try {
      const res = await fetch("/api/provider-credentials", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          provider: credentialProvider,
          display_name: credentialName,
          api_key: credentialKey,
          endpoint: credentialEndpoint || undefined,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || data.detail || "Failed to save provider key");
      }
      setCredentialKey("");
      setCredentialMessage(`${data.provider} key saved. Gateway can now inject it for upstream calls.`);
      if (isProvider(data.provider)) selectProvider(data.provider);
      await fetchCredentials();
      await fetchHealth();
    } catch (error: unknown) {
      setCredentialError(getErrorMessage(error, "Failed to save provider key"));
    } finally {
      setCredentialSaving(false);
    }
  };

  const revokeCredential = async (id: string) => {
    try {
      const res = await fetch(`/api/provider-credentials/${id}`, { method: "DELETE" });
      if (!res.ok) throw new Error("Failed to revoke provider key");
      await fetchCredentials();
      await fetchHealth();
    } catch (error: unknown) {
      setCredentialError(getErrorMessage(error, "Failed to revoke provider key"));
    }
  };

  const runGatewayTest = async () => {
    setTestBusy(true);
    setTestError(null);
    setTestResult(null);
    try {
      const res = await fetch("/api/gateway-test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Gateway test request failed");
      }
      setTestResult(data);
      await fetchHealth();
    } catch (error: unknown) {
      setTestError(getErrorMessage(error, "Gateway test request failed"));
    } finally {
      setTestBusy(false);
    }
  };

  const pendingApprovals = approvals.filter((approval) => approval.status === "PENDING");
  const activeCredentialForProvider = credentials.some(
    (credential) => credential.provider === provider && credential.status === "active",
  );

  const providerKeys = Object.keys(providerCatalog) as Provider[];
  const connectedProviders = new Set(
    credentials.filter((item) => item.status === "active").map((item) => item.provider),
  );
  const selectedCredentials = credentials.filter((item) => item.provider === provider);
  const setupStep = activeCredentialForProvider ? (testResult?.ok ? 3 : 2) : 1;
  const overallReady = healthReady && connectedProviders.size > 0;

  return (
    <div className="mx-auto max-w-7xl space-y-5 pb-10">
      <header className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h1 className="text-3xl font-extrabold tracking-tight text-[#0E1726]">Integrations</h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-[#475069]">
            Connect your AI provider, store its credentials securely, and verify requests through the AuthClaw gateway.
          </p>
        </div>
        <div className="flex w-fit items-center gap-3 rounded-[14px] border border-[#E6E9F0] bg-white px-4 py-3 shadow-[0_1px_2px_rgba(11,31,63,.05)]">
          <span className={`flex h-9 w-9 items-center justify-center rounded-full ${overallReady ? "bg-emerald-50 text-[#0F766E]" : "bg-amber-50 text-amber-700"}`}>
            {overallReady ? <CheckCircle2 className="h-5 w-5" /> : <AlertTriangle className="h-5 w-5" />}
          </span>
          <div>
            <p className="text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">Overall readiness</p>
            <p className={`text-sm font-bold ${overallReady ? "text-[#0F766E]" : "text-amber-700"}`}>
              {overallReady ? "Ready" : "Setup needed"}
            </p>
          </div>
        </div>
      </header>

      {onboardingResult && (
        <section className="rounded-[20px] border border-emerald-200 bg-emerald-50 p-5 shadow-[0_1px_2px_rgba(11,31,63,.05)]">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
            <div className="flex min-w-0 items-start gap-3">
              <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-white text-[#0F766E]"><ShieldCheck className="h-5 w-5" /></span>
              <div className="min-w-0">
                <h2 className="text-sm font-bold text-emerald-950">{onboardingResult.tenant_name} is ready</h2>
                <p className="mt-1 text-xs text-emerald-800">Copy the one-time gateway key, then connect a model provider.</p>
                <div className="mt-3 flex flex-col gap-2 sm:flex-row">
                  <code className="min-w-0 flex-1 truncate rounded-lg border border-emerald-200 bg-white px-3 py-2 text-xs">{onboardingResult.api_key}</code>
                  <button type="button" onClick={() => copy("onboarding-key", onboardingResult.api_key)} className="inline-flex items-center justify-center gap-2 rounded-lg border border-emerald-200 bg-white px-3 py-2 text-xs font-semibold text-emerald-800 hover:bg-emerald-100">
                    {copied === "onboarding-key" ? <Check className="h-4 w-4" /> : <Clipboard className="h-4 w-4" />}
                    {copied === "onboarding-key" ? "Copied" : "Copy key"}
                  </button>
                </div>
              </div>
            </div>
            <button type="button" onClick={dismissOnboardingResult} className="self-start rounded-lg px-3 py-2 text-xs font-semibold text-emerald-800 hover:bg-emerald-100">Dismiss</button>
          </div>
        </section>
      )}

      <section aria-label="Integration setup progress" className="rounded-[20px] border border-[#E6E9F0] bg-white px-5 py-5 shadow-[0_1px_2px_rgba(11,31,63,.05)]">
        <ol className="grid gap-4 md:grid-cols-3">
          {[
            ["Choose provider", "Select the service you want to connect"],
            ["Add credentials", "Securely save your provider API key"],
            ["Test connection", "Verify a request through AuthClaw"],
          ].map(([label, detail], index) => {
            const step = index + 1;
            const complete = step < setupStep || (step === 3 && Boolean(testResult?.ok));
            const active = step === setupStep;
            return (
              <li key={label} className="flex min-w-0 items-center gap-3">
                <span className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-full border text-sm font-bold ${
                  complete ? "border-[#0F766E] bg-[#0F766E] text-white" : active ? "border-[#6D28D9] bg-[#6D28D9] text-white" : "border-[#DDE3EC] text-[#6B7488]"
                }`}>{complete ? <Check className="h-4 w-4" /> : step}</span>
                <div className="min-w-0">
                  <p className="text-sm font-bold text-[#0E1726]">{label}</p>
                  <p className="mt-0.5 truncate text-[11px] text-[#6B7488]">{detail}</p>
                </div>
              </li>
            );
          })}
        </ol>
      </section>

      <section className="overflow-hidden rounded-[20px] border border-[#E6E9F0] bg-white shadow-[0_1px_2px_rgba(11,31,63,.05),0_12px_30px_-18px_rgba(11,31,63,.18)]">
        <div className="grid lg:grid-cols-[minmax(0,.9fr)_minmax(0,1.1fr)]">
          <div className="border-b border-[#E6E9F0] p-5 sm:p-6 lg:border-b-0 lg:border-r">
            <h2 className="text-base font-bold text-[#0E1726]">Choose provider</h2>
            <p className="mt-1 text-xs text-[#6B7488]">Select a provider to configure or manage.</p>
            <div className="mt-5 space-y-2.5">
              {providerKeys.map((id) => {
                const item = providerCatalog[id];
                const connected = connectedProviders.has(id);
                const isSelected = provider === id;
                return (
                  <button key={id} type="button" onClick={() => selectProvider(id)} aria-pressed={isSelected}
                    className={`flex w-full items-center gap-3 rounded-[14px] border p-3.5 text-left transition ${isSelected ? "border-[#6D28D9] bg-[#F8F5FF]" : "border-[#E6E9F0] hover:border-[#A78BFA] hover:bg-[#FBFAFF]"}`}>
                    <span className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-[12px] border bg-white ${isSelected ? "border-[#C4B5FD]" : "border-[#EDF0F5]"}`}>
                      <Image
                        src={providerLogos[id]}
                        alt=""
                        width={24}
                        height={24}
                        loading="eager"
                        unoptimized
                        className="h-6 w-6 object-contain"
                      />
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block text-sm font-bold text-[#0E1726]">{item.shortLabel}</span>
                      <span className="mt-0.5 block truncate text-[11px] text-[#6B7488]">{item.label}</span>
                    </span>
                    <span className={`hidden items-center gap-1.5 text-[11px] font-semibold sm:flex ${connected ? "text-[#0F766E]" : "text-[#6B7488]"}`}>
                      <span className={`h-2 w-2 rounded-full ${connected ? "bg-emerald-500" : "bg-[#C5CBD6]"}`} />
                      {connected ? "Connected" : "Not connected"}
                    </span>
                    <ChevronRight className={`h-4 w-4 ${isSelected ? "text-[#6D28D9]" : "text-[#A8B0C0]"}`} />
                  </button>
                );
              })}
            </div>
            <div className="mt-5 flex gap-2 border-t border-[#E6E9F0] pt-4 text-[11px] leading-5 text-[#6B7488]">
              <LockKeyhole className="mt-0.5 h-4 w-4 shrink-0 text-[#6D28D9]" />
              Credentials are encrypted and never returned after save.
            </div>
          </div>
          <div className="p-5 sm:p-6">
            <div className="flex flex-col gap-3 border-b border-[#E6E9F0] pb-5 sm:flex-row sm:justify-between">
              <div>
                <p className="text-[10px] font-bold uppercase tracking-wider text-[#6D28D9]">Selected provider</p>
                <h2 className="mt-1 text-xl font-extrabold text-[#0E1726]">Set up {selected.shortLabel}</h2>
                <p className="mt-1 text-xs text-[#6B7488]">Add or rotate the credential used for governed upstream requests.</p>
              </div>
              <span className={`inline-flex h-fit w-fit items-center gap-2 rounded-full px-3 py-1.5 text-[11px] font-bold ${activeCredentialForProvider ? "bg-emerald-50 text-[#0F766E]" : "bg-[#F5F7FA] text-[#6B7488]"}`}>
                <span className={`h-2 w-2 rounded-full ${activeCredentialForProvider ? "bg-emerald-500" : "bg-[#C5CBD6]"}`} />
                {activeCredentialForProvider ? "Credential active" : "Credential required"}
              </span>
            </div>

            <div className="mt-5 space-y-4">
              <label className="block">
                <span className="mb-1.5 block text-xs font-bold text-[#0E1726]">Credential name</span>
                <input value={credentialName} onChange={(event) => setCredentialName(event.target.value)} placeholder={`Production ${selected.shortLabel} key`}
                  className="w-full rounded-[10px] border border-[#DDE3EC] px-3.5 py-2.5 text-sm text-[#0E1726] outline-none transition placeholder:text-[#A8B0C0] focus:border-[#6D28D9] focus:ring-2 focus:ring-[#F1ECFE]" />
              </label>
              <label className="block">
                <span className="mb-1.5 block text-xs font-bold text-[#0E1726]">Provider API key</span>
                <span className="relative block">
                  <input type={showCredentialKey ? "text" : "password"} value={credentialKey} onChange={(event) => setCredentialKey(event.target.value)}
                    placeholder={`Paste your ${selected.shortLabel} API key`} autoComplete="off"
                    className="w-full rounded-[10px] border border-[#DDE3EC] px-3.5 py-2.5 pr-11 text-sm text-[#0E1726] outline-none transition placeholder:text-[#A8B0C0] focus:border-[#6D28D9] focus:ring-2 focus:ring-[#F1ECFE]" />
                  <button type="button" onClick={() => setShowCredentialKey((current) => !current)} aria-label={showCredentialKey ? "Hide provider API key" : "Show provider API key"}
                    className="absolute inset-y-0 right-0 flex w-11 items-center justify-center text-[#6B7488] hover:text-[#0E1726]">
                    {showCredentialKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </span>
              </label>
              <label className="block">
                <span className="mb-1.5 block text-xs font-bold text-[#0E1726]">Endpoint URL <span className="font-medium text-[#6B7488]">(optional)</span></span>
                <input value={credentialEndpoint} onChange={(event) => setCredentialEndpoint(event.target.value)} placeholder={selected.defaultEndpoint}
                  className="w-full rounded-[10px] border border-[#DDE3EC] px-3.5 py-2.5 text-sm text-[#0E1726] outline-none transition placeholder:text-[#A8B0C0] focus:border-[#6D28D9] focus:ring-2 focus:ring-[#F1ECFE]" />
              </label>
            </div>

            <div aria-live="polite" className="mt-4 min-h-5 text-xs">
              {credentialMessage && <p className="text-[#0F766E]">{credentialMessage}</p>}
              {credentialError && <p className="text-red-700">{credentialError}</p>}
            </div>
            <div className="mt-3 flex flex-col gap-3 sm:flex-row">
              <button type="button" onClick={() => void saveCredential()} disabled={credentialSaving || credentialKey.length < 8}
                className="inline-flex items-center justify-center gap-2 rounded-[10px] bg-[#6D28D9] px-4 py-2.5 text-sm font-semibold text-white hover:bg-[#7C3AED] disabled:cursor-not-allowed disabled:opacity-50">
                <LockKeyhole className="h-4 w-4" />{credentialSaving ? "Saving credential..." : "Save credential"}
              </button>
              <button type="button" onClick={() => void runGatewayTest()} disabled={testBusy || !activeCredentialForProvider}
                className="inline-flex items-center justify-center gap-2 rounded-[10px] border border-[#DDE3EC] px-4 py-2.5 text-sm font-semibold text-[#0E1726] hover:border-[#A78BFA] hover:bg-[#F8F5FF] disabled:cursor-not-allowed disabled:opacity-50">
                <Play className="h-4 w-4 text-[#6D28D9]" />{testBusy ? "Testing connection..." : "Run connection test"}
              </button>
            </div>
            {!activeCredentialForProvider && credentialsLoaded && <p className="mt-3 text-[11px] text-amber-700">Save a {selected.shortLabel} credential before testing the connection.</p>}
            {testError && <div className="mt-4 rounded-[10px] border border-red-200 bg-red-50 p-3 text-xs text-red-700">{testError}</div>}
            {testResult && (
              <div className={`mt-4 rounded-[12px] border p-4 ${testResult.ok ? "border-emerald-200 bg-emerald-50" : "border-amber-200 bg-amber-50"}`}>
                <div className="flex flex-wrap items-center gap-2">
                  {testResult.ok ? <CheckCircle2 className="h-5 w-5 text-[#0F766E]" /> : <AlertTriangle className="h-5 w-5 text-amber-700" />}
                  <p className="text-sm font-bold text-[#0E1726]">{testResult.ok ? "Connection verified" : `Gateway returned ${testResult.status}`}</p>
                  <span className="text-[11px] text-[#6B7488]">{testResult.duration_ms} ms</span>
                </div>
                <p className="mt-2 font-mono text-[10px] text-[#475069]">Request ID: {testResult.request_id}</p>
                {testResult.checks && <div className="mt-3 grid gap-2 sm:grid-cols-2">{testResult.checks.map((check) => (
                  <div key={check.label} className="flex gap-2 rounded-lg bg-white/80 p-2.5">
                    {check.ok ? <Check className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[#0F766E]" /> : <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-700" />}
                    <div><p className="text-[11px] font-bold text-[#0E1726]">{check.label}</p><p className="mt-0.5 text-[10px] text-[#6B7488]">{check.detail}</p></div>
                  </div>
                ))}</div>}
              </div>
            )}

            {selectedCredentials.length > 0 && (
              <div className="mt-5 border-t border-[#E6E9F0] pt-4">
                <p className="mb-2 text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">Saved credentials</p>
                <div className="space-y-2">{selectedCredentials.map((credential) => (
                  <div key={credential.id} className="flex items-center gap-3 rounded-[10px] bg-[#F5F7FA] px-3 py-2.5">
                    <KeyRound className="h-4 w-4 shrink-0 text-[#6D28D9]" />
                    <div className="min-w-0 flex-1"><p className="truncate text-xs font-bold text-[#0E1726]">{credential.display_name}</p><p className="mt-0.5 text-[10px] text-[#6B7488]">{credential.status} · added {new Date(credential.created_at).toLocaleDateString()}</p></div>
                    <button type="button" onClick={() => void revokeCredential(credential.id)} aria-label={`Revoke ${credential.display_name}`}
                      className="inline-flex items-center gap-1.5 rounded-lg px-2.5 py-2 text-[11px] font-semibold text-red-700 hover:bg-red-50"><Trash2 className="h-3.5 w-3.5" />Revoke</button>
                  </div>
                ))}</div>
              </div>
            )}
          </div>
        </div>
      </section>

      <div className="grid gap-5 xl:grid-cols-[.8fr_1.35fr_.85fr]">
        <section className="overflow-hidden rounded-[20px] border border-[#E6E9F0] bg-white shadow-[0_1px_2px_rgba(11,31,63,.05)]">
          <div className="flex items-start justify-between border-b border-[#E6E9F0] px-5 py-4">
            <div><h2 className="text-sm font-bold text-[#0E1726]">Integration health</h2><p className="mt-1 text-[11px] text-[#6B7488]">Gateway readiness checks</p></div>
            <button type="button" onClick={() => void fetchHealth()} aria-label="Recheck integration health" className="rounded-lg p-2 text-[#6B7488] hover:bg-[#F5F7FA] hover:text-[#6D28D9]"><RefreshCw className="h-4 w-4" /></button>
          </div>
          <div className="p-3">
            {healthError && <p className="rounded-lg bg-red-50 p-3 text-xs text-red-700">{healthError}</p>}
            {!healthError && healthItems.length === 0 && <p className="p-2 text-xs text-[#6B7488]">Health checks have not run yet.</p>}
            <div className="divide-y divide-[#E6E9F0]">{healthItems.map((item) => (
              <div key={item.key} className="flex items-start gap-3 px-2 py-3">
                <span className={`mt-0.5 h-2.5 w-2.5 shrink-0 rounded-full ${item.ok ? "bg-emerald-500" : "bg-amber-400"}`} />
                <div><p className="text-xs font-bold text-[#0E1726]">{item.label}</p><p className="mt-1 text-[10px] leading-4 text-[#6B7488]">{item.detail}</p></div>
              </div>
            ))}</div>
          </div>
        </section>

        <section className="overflow-hidden rounded-[20px] border border-[#E6E9F0] bg-white shadow-[0_1px_2px_rgba(11,31,63,.05)]">
          <div className="border-b border-[#E6E9F0] px-5 pt-4">
            <div className="flex items-start justify-between gap-3">
              <div><h2 className="text-sm font-bold text-[#0E1726]">Developer quickstart</h2><p className="mt-1 text-[11px] text-[#6B7488]">Use the selected {selected.shortLabel} route</p></div>
              <button type="button" onClick={() => copy(codeTab === "curl" ? "curl" : "python-sdk", codeTab === "curl" ? curlCommand : pythonSdkSnippet)}
                className="inline-flex items-center gap-2 rounded-lg px-3 py-2 text-xs font-semibold text-[#475069] hover:bg-[#F5F7FA] hover:text-[#6D28D9]">
                {copied === (codeTab === "curl" ? "curl" : "python-sdk") ? <Check className="h-4 w-4" /> : <Clipboard className="h-4 w-4" />}{copied === (codeTab === "curl" ? "curl" : "python-sdk") ? "Copied" : "Copy"}
              </button>
            </div>
            <div className="mt-4 flex gap-5">{(["curl", "python"] as const).map((tab) => (
              <button key={tab} type="button" onClick={() => setCodeTab(tab)} className={`border-b-2 pb-2 text-xs font-bold capitalize ${codeTab === tab ? "border-[#6D28D9] text-[#6D28D9]" : "border-transparent text-[#6B7488]"}`}>{tab}</button>
            ))}</div>
          </div>
          <div className="p-5"><pre className="max-h-64 overflow-auto rounded-[12px] border border-[#E6E9F0] bg-[#F8FAFC] p-4 text-[11px] leading-5 text-[#0E1726]"><code>{codeTab === "curl" ? curlCommand : pythonSdkSnippet}</code></pre></div>
        </section>

        <section className="overflow-hidden rounded-[20px] border border-[#E6E9F0] bg-white shadow-[0_1px_2px_rgba(11,31,63,.05)]">
          <div className="flex items-start justify-between border-b border-[#E6E9F0] px-5 py-4">
            <div><h2 className="text-sm font-bold text-[#0E1726]">Pending approvals</h2><p className="mt-1 text-[11px] text-[#6B7488]">High-risk gateway requests</p></div>
            {pendingApprovals.length > 0 && <span className="rounded-full bg-amber-50 px-2.5 py-1 text-[11px] font-bold text-amber-700">{pendingApprovals.length}</span>}
          </div>
          <div className="p-3">
            {approvalError && <p className="rounded-lg bg-red-50 p-3 text-xs text-red-700">{approvalError}</p>}
            {!approvalError && pendingApprovals.length === 0 && <div className="flex items-center gap-3 p-2"><CheckCircle2 className="h-5 w-5 text-[#0F766E]" /><p className="text-xs text-[#475069]">No requests need attention.</p></div>}
            <div className="divide-y divide-[#E6E9F0]">{pendingApprovals.slice(0, 3).map((approval) => (
              <div key={approval.id} className="px-2 py-3">
                <p className="truncate text-xs font-bold text-[#0E1726]">{approval.action_payload.rule_name || "Custom policy match"}</p>
                <p className="mt-1 line-clamp-2 text-[10px] leading-4 text-[#6B7488]">{approval.action_payload.reason || approval.action_description}</p>
                <div className="mt-2 flex gap-2">
                  <button type="button" onClick={() => void decideApproval(approval.id, "reject")} disabled={approvalBusy === approval.id} className="rounded-lg px-2.5 py-1.5 text-[11px] font-semibold text-red-700 hover:bg-red-50 disabled:opacity-50">Reject</button>
                  <button type="button" onClick={() => handleGatewayApproveClick(approval)} disabled={approvalBusy === approval.id} className="rounded-lg bg-[#0F766E] px-2.5 py-1.5 text-[11px] font-semibold text-white hover:bg-teal-700 disabled:opacity-50">Review & approve</button>
                </div>
              </div>
            ))}</div>
            {pendingApprovals.length > 3 && <a href="/approvals" className="mt-2 flex items-center gap-1.5 px-2 py-2 text-xs font-bold text-[#6D28D9] hover:underline">View all approvals <ArrowRight className="h-3.5 w-3.5" /></a>}
          </div>
        </section>
      </div>

      <section className="flex flex-col gap-3 rounded-[16px] border border-[#E6E9F0] bg-white px-5 py-4 text-xs text-[#475069] sm:flex-row sm:items-center sm:justify-between">
        <div className="flex min-w-0 items-center gap-3"><Code2 className="h-4 w-4 shrink-0 text-[#6D28D9]" /><span className="truncate font-mono">{gatewayUrl}</span></div>
        <button type="button" onClick={() => copy("gateway", gatewayUrl)} className="inline-flex shrink-0 items-center justify-center gap-2 rounded-lg border border-[#E6E9F0] px-3 py-2 font-semibold hover:border-[#A78BFA] hover:bg-[#F8F5FF]">
          {copied === "gateway" ? <Check className="h-4 w-4 text-[#0F766E]" /> : <Clipboard className="h-4 w-4" />}{copied === "gateway" ? "Copied" : "Copy gateway URL"}
        </button>
      </section>

      {gatewayMfaTarget && (
        <MfaChallengeModal code={gatewayTotpCode} setCode={setGatewayTotpCode} busy={gatewayMfaBusy} error={gatewayMfaError}
          onClose={() => setGatewayMfaTarget(null)} onSubmit={handleGatewayMfaSubmit} accentClass="text-emerald-400"
          description="Confirm your administrator identity before allowing this gateway request to pass. Enter the 6-digit TOTP code from your authenticator app (or a backup recovery code)."
          submitLabel="Authorize Passage" />
      )}
    </div>
  );
}
