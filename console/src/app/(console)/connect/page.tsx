"use client";

import React, { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Check,
  Clipboard,
  Code2,
  KeyRound,
  Link2,
  Play,
  Route,
  ShieldCheck,
} from "lucide-react";
import MfaChallengeModal from "@/components/mfa-challenge-modal";
import { fetchJson } from "@/lib/client-fetch";
import { flashCopy } from "@/lib/clipboard";
import { getErrorMessage } from "@/lib/errors";
import { isProvider, providerCatalog, type Provider } from "@/lib/providers";

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
  const [provider, setProvider] = useState<Provider>("gemini");
  const [copied, setCopied] = useState<string | null>(null);
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
  const gatewayUrl = onboardingResult?.gateway_url || process.env.NEXT_PUBLIC_GATEWAY_URL || "http://localhost:18080";
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

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <div className="flex flex-col gap-2">
        <div className="flex items-center gap-2 text-emerald-400 text-xs font-bold uppercase tracking-wider">
          <ShieldCheck className="w-4 h-4" />
          Guided onboarding path
        </div>
        <h1 className="text-3xl font-extrabold tracking-tight text-[#0E1726]">Connect Your AI App</h1>
        <p className="text-sm text-[#475069] max-w-3xl">
          Point an existing chatbot or AI service at the AuthClaw gateway URL. AuthClaw checks the tenant key,
          applies redaction and policy controls, forwards the request to the configured model provider, and records
          the governance evidence.
        </p>
      </div>

      {onboardingResult && (
        <section className="rounded-[20px] border border-emerald-200 bg-emerald-50 overflow-hidden shadow-[0_1px_2px_rgba(11,31,63,.05),0_12px_30px_-12px_rgba(11,31,63,.18)]">
          <div className="border-b border-emerald-200 px-5 py-4">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
              <div>
                <div className="flex items-center gap-2 text-sm font-bold text-emerald-900">
                  <ShieldCheck className="h-4 w-4 text-emerald-400" />
                  Tenant Ready
                </div>
                <p className="mt-1 text-xs text-emerald-700">
                  {onboardingResult.tenant_name} is signed in. Copy the first gateway key now, then save a provider key below.
                </p>
              </div>
              <button
                type="button"
                onClick={dismissOnboardingResult}
                className="rounded-[10px] border border-emerald-200 px-3 py-2 text-xs font-semibold text-emerald-800 hover:bg-emerald-100"
              >
                Hide
              </button>
            </div>
          </div>

          <div className="grid gap-4 p-5 lg:grid-cols-2">
            <div className="space-y-4">
              <div>
                <div className="mb-2 flex items-center justify-between gap-3">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-emerald-200/70">
                    First AuthClaw Gateway Key
                  </span>
                  <button
                    type="button"
                    onClick={() => copy("onboarding-key", onboardingResult.api_key)}
                    className="inline-flex items-center gap-1 text-xs font-semibold text-emerald-700 hover:text-emerald-900"
                  >
                    {copied === "onboarding-key" ? <Check className="h-3.5 w-3.5" /> : <Clipboard className="h-3.5 w-3.5" />}
                    {copied === "onboarding-key" ? "Copied" : "Copy"}
                  </button>
                </div>
                <pre className="overflow-x-auto rounded-[10px] border border-emerald-200 bg-white p-3 text-xs text-emerald-900">
                  {onboardingResult.api_key}
                </pre>
                <p className="mt-2 text-[10px] text-emerald-700">This raw key is shown from onboarding only. Store it before hiding this panel.</p>
              </div>

              <div>
                <div className="mb-2 flex items-center justify-between gap-3">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-emerald-700">Gateway URL</span>
                  <button
                    type="button"
                    onClick={() => copy("onboarding-gateway", onboardingResult.gateway_url)}
                    className="inline-flex items-center gap-1 text-xs font-semibold text-emerald-700 hover:text-emerald-900"
                  >
                    {copied === "onboarding-gateway" ? <Check className="h-3.5 w-3.5" /> : <Clipboard className="h-3.5 w-3.5" />}
                    {copied === "onboarding-gateway" ? "Copied" : "Copy"}
                  </button>
                </div>
                <pre className="overflow-x-auto rounded-[10px] border border-emerald-200 bg-white p-3 text-xs text-emerald-900">
                  {onboardingResult.gateway_url}
                </pre>
              </div>
            </div>

            <div>
              <div className="mb-2 flex items-center justify-between gap-3">
                <span className="text-[10px] font-bold uppercase tracking-wider text-emerald-700">PowerShell Starter Request</span>
                <button
                  type="button"
                  onClick={() => copy("onboarding-powershell", onboardingResult.powershell_snippet)}
                  className="inline-flex items-center gap-1 text-xs font-semibold text-emerald-700 hover:text-emerald-900"
                >
                  {copied === "onboarding-powershell" ? <Check className="h-3.5 w-3.5" /> : <Clipboard className="h-3.5 w-3.5" />}
                  {copied === "onboarding-powershell" ? "Copied" : "Copy"}
                </button>
              </div>
              <pre className="max-h-80 overflow-auto rounded-[10px] border border-emerald-200 bg-white p-3 text-xs text-emerald-900">
                {onboardingResult.powershell_snippet}
              </pre>
              <button
                type="button"
                onClick={() => copy("onboarding-curl", onboardingResult.curl_snippet)}
                className="mt-3 inline-flex items-center gap-2 rounded-[10px] bg-emerald-600 px-3 py-2 text-xs font-semibold text-white hover:bg-emerald-500"
              >
                {copied === "onboarding-curl" ? <Check className="h-4 w-4" /> : <Clipboard className="h-4 w-4" />}
                {copied === "onboarding-curl" ? "Copied curl" : "Copy curl instead"}
              </button>
            </div>
          </div>
        </section>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <section className="rounded-[20px] bg-white border border-[#E6E9F0] p-5 shadow-[0_1px_2px_rgba(11,31,63,.05),0_12px_30px_-12px_rgba(11,31,63,.18)]">
          <div className="flex items-center gap-2 mb-4">
            <Link2 className="w-4 h-4 text-[#6D28D9]" />
            <h2 className="text-sm font-bold text-[#0E1726]">1. Use The Gateway URL</h2>
          </div>
          <p className="text-xs text-[#6B7488] mb-3">Replace the model provider base URL in the customer app.</p>
          <div className="flex items-center gap-2 rounded-[10px] border border-[#E6E9F0] bg-[#F5F7FA] px-3 py-2">
            <code className="text-xs text-[#0E1726] flex-1 truncate">{gatewayUrl}</code>
            <button
              onClick={() => copy("gateway", gatewayUrl)}
              className="p-1.5 rounded bg-white hover:bg-[#F1ECFE] text-[#475069] border border-[#E6E9F0]"
              aria-label="Copy gateway URL"
            >
              {copied === "gateway" ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Clipboard className="w-3.5 h-3.5" />}
            </button>
          </div>
        </section>

        <section className="rounded-[20px] bg-white border border-[#E6E9F0] p-5 shadow-[0_1px_2px_rgba(11,31,63,.05),0_12px_30px_-12px_rgba(11,31,63,.18)]">
          <div className="flex items-center gap-2 mb-4">
            <KeyRound className="w-4 h-4 text-amber-400" />
            <h2 className="text-sm font-bold text-[#0E1726]">2. Send AuthClaw Key</h2>
          </div>
          <p className="text-xs text-[#6B7488] mb-3">
            Runtime traffic uses an AuthClaw gateway key, not the customer provider key.
          </p>
          <div className="rounded-[10px] border border-[#E6E9F0] bg-[#F5F7FA] px-3 py-2">
            <code className="text-xs text-[#0E1726]">Authorization: Bearer {"<AUTHCLAW_GATEWAY_KEY>"}</code>
          </div>
        </section>

        <section className="rounded-[20px] bg-white border border-[#E6E9F0] p-5 shadow-[0_1px_2px_rgba(11,31,63,.05),0_12px_30px_-12px_rgba(11,31,63,.18)]">
          <div className="flex items-center gap-2 mb-4">
            <Route className="w-4 h-4 text-sky-400" />
            <h2 className="text-sm font-bold text-[#0E1726]">3. Select Provider Route</h2>
          </div>
          <p className="text-xs text-[#6B7488] mb-3">AuthClaw uses the provider route to apply the right policy and adapter.</p>
          <select
            value={provider}
            onChange={(event) => selectProvider(event.target.value as Provider)}
            className="w-full px-3 py-2 rounded-[10px] bg-[#F5F7FA] border border-[#E6E9F0] text-[#0E1726] text-xs focus:outline-none focus:border-[#6D28D9]"
          >
            {Object.entries(providerCatalog).map(([id, item]) => (
              <option key={id} value={id}>
                {item.label}
              </option>
            ))}
          </select>
        </section>
      </div>

      <section className="rounded-[20px] bg-white border border-[#E6E9F0] overflow-hidden shadow-[0_1px_2px_rgba(11,31,63,.05),0_12px_30px_-12px_rgba(11,31,63,.18)]">
        <div className="px-5 py-4 border-b border-[#E6E9F0] flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div>
            <div className="flex items-center gap-2 text-[#0E1726] font-bold text-sm">
              <ShieldCheck className={healthReady ? "w-4 h-4 text-emerald-400" : "w-4 h-4 text-amber-400"} />
              Integration Health
            </div>
            <p className="text-xs text-[#6B7488] mt-1">
              Checks whether the Lite gateway path is ready for a test request.
            </p>
          </div>
          <button
            onClick={() => void fetchHealth()}
            className="px-3 py-2 rounded-[10px] bg-[#F5F7FA] hover:bg-[#F1ECFE] text-xs font-semibold text-[#475069] border border-[#E6E9F0]"
          >
            Recheck
          </button>
        </div>
        {healthError && (
          <div className="m-5 rounded-lg border border-red-500/20 bg-red-500/10 p-3 text-xs text-red-700">
            {healthError}
          </div>
        )}
        <div className="grid grid-cols-1 md:grid-cols-5 gap-3 p-5">
          {healthItems.length === 0 ? (
            <p className="text-xs text-[#6B7488] md:col-span-5">Health checks have not run yet.</p>
          ) : (
            healthItems.map((item) => (
              <div key={item.key} className="rounded-[10px] border border-[#E6E9F0] bg-[#F5F7FA] p-3">
                <div className="flex items-center gap-2">
                  {item.ok ? (
                    <Check className="w-4 h-4 text-emerald-400" />
                  ) : (
                    <AlertTriangle className="w-4 h-4 text-amber-400" />
                  )}
                  <span className="text-xs font-bold text-[#0E1726]">{item.label}</span>
                </div>
                <p className="text-[10px] text-[#6B7488] mt-2">{item.detail}</p>
              </div>
            ))
          )}
        </div>
      </section>

      <section className="rounded-[20px] bg-white border border-[#E6E9F0] overflow-hidden shadow-[0_1px_2px_rgba(11,31,63,.05),0_12px_30px_-12px_rgba(11,31,63,.18)]">
        <div className="px-5 py-4 border-b border-[#E6E9F0]">
          <div className="flex items-center gap-2 text-[#0E1726] font-bold text-sm">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            Provider Production Readiness
          </div>
          <p className="text-xs text-[#6B7488] mt-1">
            Payload and streaming contracts are pinned in gateway tests and checked in CI.
          </p>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-3 p-5">
          {Object.entries(providerCatalog).map(([id, item]) => {
            const active = credentials.some((credential) => credential.provider === id && credential.status === "active");
            return (
              <div key={id} className="rounded-[10px] border border-[#E6E9F0] bg-[#F5F7FA] p-3">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <div className="text-xs font-bold text-[#0E1726]">{item.shortLabel}</div>
                    <div className="mt-1 text-[10px] text-[#6B7488]">{item.lastReviewed}</div>
                  </div>
                  <span className="rounded bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase text-emerald-700">
                    {item.readiness}
                  </span>
                </div>
                <p className="mt-3 text-[10px] text-[#475069]">{item.payloadContract}</p>
                <p className="mt-1 text-[10px] text-[#475069]">{item.streamingContract}</p>
                <div className="mt-3 flex items-center gap-1 text-[10px] text-[#6B7488]">
                  {active ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />}
                  {active ? "Connected" : "Provider key needed"}
                </div>
              </div>
            );
          })}
        </div>
      </section>

      <section className="rounded-[20px] bg-white border border-[#E6E9F0] overflow-hidden shadow-[0_1px_2px_rgba(11,31,63,.05),0_12px_30px_-12px_rgba(11,31,63,.18)]">
        <div className="px-5 py-4 border-b border-[#E6E9F0]">
          <div className="flex items-center gap-2 text-[#0E1726] font-bold text-sm">
            <KeyRound className="w-4 h-4 text-amber-400" />
            Provider Key Vault
          </div>
          <p className="text-xs text-[#6B7488] mt-1">
            Store the customer model-provider key once. AuthClaw uses this upstream key after governance checks pass.
          </p>
        </div>

        <div className="p-5 grid grid-cols-1 lg:grid-cols-4 gap-3">
          <label className="block">
            <span className="block text-[10px] uppercase tracking-wider font-bold text-[#6B7488] mb-1.5">Provider</span>
            <select
              value={credentialProvider}
              onChange={(event) => selectProvider(event.target.value as Provider)}
              className="w-full px-3 py-2 rounded-[10px] bg-[#F5F7FA] border border-[#E6E9F0] text-[#0E1726] text-xs focus:outline-none focus:border-[#6D28D9]"
            >
              <option value="openai">OpenAI</option>
              <option value="anthropic">Anthropic</option>
              <option value="cohere">Cohere</option>
              <option value="azure_openai">Azure OpenAI</option>
              <option value="gemini">Gemini</option>
            </select>
          </label>
          <label className="block">
            <span className="block text-[10px] uppercase tracking-wider font-bold text-[#6B7488] mb-1.5">Display Name</span>
            <input
              value={credentialName}
              onChange={(event) => setCredentialName(event.target.value)}
              className="w-full px-3 py-2 rounded-[10px] bg-[#F5F7FA] border border-[#E6E9F0] text-[#0E1726] text-xs focus:outline-none focus:border-[#6D28D9]"
            />
          </label>
          <label className="block">
            <span className="block text-[10px] uppercase tracking-wider font-bold text-[#6B7488] mb-1.5">Provider API Key</span>
            <input
              type="password"
              value={credentialKey}
              onChange={(event) => setCredentialKey(event.target.value)}
              placeholder="Paste provider key"
              className="w-full px-3 py-2 rounded-[10px] bg-[#F5F7FA] border border-[#E6E9F0] text-[#0E1726] text-xs focus:outline-none focus:border-[#6D28D9]"
            />
          </label>
          <label className="block">
            <span className="block text-[10px] uppercase tracking-wider font-bold text-[#6B7488] mb-1.5">Endpoint Override</span>
            <input
              value={credentialEndpoint}
              onChange={(event) => setCredentialEndpoint(event.target.value)}
              placeholder="Optional"
              className="w-full px-3 py-2 rounded-[10px] bg-[#F5F7FA] border border-[#E6E9F0] text-[#0E1726] text-xs focus:outline-none focus:border-[#6D28D9]"
            />
          </label>
        </div>

        <div className="px-5 pb-5 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3">
          <div className="text-xs">
            {credentialMessage && <p className="text-emerald-700">{credentialMessage}</p>}
            {credentialError && <p className="text-red-700">{credentialError}</p>}
            {!credentialMessage && !credentialError && (
              <p className="text-[#6B7488]">Raw provider keys are encrypted and never returned after save.</p>
            )}
          </div>
          <button
            onClick={() => void saveCredential()}
            disabled={credentialSaving || credentialKey.length < 8}
            className="inline-flex items-center justify-center gap-2 px-3 py-2 rounded-[10px] bg-[#6D28D9] hover:bg-[#7C3AED] text-xs font-semibold text-white disabled:opacity-50"
          >
            <Check className="w-4 h-4" />
            {credentialSaving ? "Saving..." : "Save Provider Key"}
          </button>
        </div>

        <div className="mx-5 mb-5 rounded-[10px] border border-[#E6E9F0] bg-[#F5F7FA] p-4">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <div className="flex items-center gap-2 text-sm font-bold text-[#0E1726]">
                <Play className="h-4 w-4 text-emerald-400" />
                Test Gateway Request
              </div>
              <p className="mt-1 text-xs text-[#6B7488]">
                Sends a safe sample prompt through AuthClaw using the current tenant key and selected provider route.
              </p>
            </div>
            <button
              onClick={() => void runGatewayTest()}
              disabled={testBusy || !activeCredentialForProvider}
              className="inline-flex items-center justify-center gap-2 rounded-[10px] bg-emerald-600 px-3 py-2 text-xs font-semibold text-white hover:bg-emerald-500 disabled:opacity-50"
            >
              <Play className="h-4 w-4" />
              {testBusy ? "Testing..." : `Test ${providerCatalog[provider].shortLabel} key`}
            </button>
          </div>

          {!credentialsLoaded && (
            <p className="mt-3 text-xs text-[#6B7488]">Loading provider keys...</p>
          )}
          {credentialsLoaded && !activeCredentialForProvider && (
            <p className="mt-3 text-xs text-amber-700">
              Save an active {providerCatalog[provider].shortLabel} provider key first, then run the gateway test.
              {provider === "openai" ? " You can leave OpenAI untested until you have an OpenAI API key." : ""}
            </p>
          )}
          {testError && (
            <div className="mt-3 rounded-lg border border-red-500/20 bg-red-500/10 p-3 text-xs text-red-700">
              {testError}
            </div>
          )}
          {testResult && (
            <div
              className={`mt-3 rounded-lg border p-3 text-xs ${
                testResult.ok
                  ? "border-emerald-500/20 bg-emerald-500/10 text-emerald-800"
                  : "border-amber-500/20 bg-amber-500/10 text-amber-800"
              }`}
            >
              <div className="flex flex-wrap items-center gap-2">
                {testResult.ok ? <Check className="h-4 w-4" /> : <AlertTriangle className="h-4 w-4" />}
                <span className="font-bold">
                  {testResult.ok ? "Gateway request succeeded" : `Gateway returned ${testResult.status}`}
                </span>
                <span className="text-[#475069]">Request ID: {testResult.request_id}</span>
                <span className="text-[#475069]">{testResult.duration_ms}ms</span>
                {testResult.content_type && <span className="text-[#475069]">{testResult.content_type}</span>}
              </div>
              {testResult.contract && (
                <div className="mt-3 grid grid-cols-1 gap-2 md:grid-cols-2">
                  <div className="rounded border border-[#E6E9F0] bg-white p-2">
                    <div className="text-[10px] font-bold uppercase text-[#6B7488]">Payload</div>
                    <div className="mt-1 text-[11px] text-[#0E1726]">{testResult.contract.payload}</div>
                  </div>
                  <div className="rounded border border-[#E6E9F0] bg-white p-2">
                    <div className="text-[10px] font-bold uppercase text-[#6B7488]">Streaming</div>
                    <div className="mt-1 text-[11px] text-[#0E1726]">{testResult.contract.streaming}</div>
                  </div>
                </div>
              )}
              {testResult.checks && (
                <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-4">
                  {testResult.checks.map((check) => (
                    <div key={check.label} className="rounded border border-[#E6E9F0] bg-white p-2">
                      <div className="flex items-center gap-1 text-[10px] font-bold text-[#0E1726]">
                        {check.ok ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />}
                        {check.label}
                      </div>
                      <div className="mt-1 text-[10px] text-[#6B7488]">{check.detail}</div>
                    </div>
                  ))}
                </div>
              )}
              <pre className="mt-3 max-h-56 overflow-auto rounded border border-[#E6E9F0] bg-white p-3 text-[11px] text-[#0E1726]">
                {JSON.stringify(testResult.response ?? testResult.raw ?? testResult.error ?? {}, null, 2)}
              </pre>
            </div>
          )}
        </div>

        <div className="border-t border-[#E6E9F0] divide-y divide-[#E6E9F0]">
          {credentials.length === 0 ? (
            <div className="p-5 text-xs text-[#6B7488]">No provider keys configured yet.</div>
          ) : (
            credentials.map((credential) => (
              <div key={credential.id} className="p-5 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-bold text-[#0E1726]">{credential.display_name}</span>
                    <span className="px-2 py-0.5 rounded bg-[#F5F7FA] text-[10px] font-semibold uppercase text-[#475069] border border-[#E6E9F0]">
                      {credential.provider}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/20 text-[10px] font-semibold uppercase text-emerald-700">
                      {credential.status}
                    </span>
                  </div>
                  <p className="text-[10px] text-[#6B7488] mt-1">
                    Created {new Date(credential.created_at).toLocaleString()}
                    {credential.endpoint ? ` / endpoint override configured` : ""}
                  </p>
                </div>
                <button
                  onClick={() => void revokeCredential(credential.id)}
                  className="px-3 py-2 rounded-[10px] bg-red-500/10 hover:bg-red-500/20 border border-red-500/20 text-xs font-semibold text-red-700"
                >
                  Revoke
                </button>
              </div>
            ))
          )}
        </div>
      </section>

      <section className="rounded-[20px] bg-white border border-[#E6E9F0] overflow-hidden shadow-[0_1px_2px_rgba(11,31,63,.05),0_12px_30px_-12px_rgba(11,31,63,.18)]">
        <div className="px-5 py-4 border-b border-[#E6E9F0] flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div>
            <div className="flex items-center gap-2 text-[#0E1726] font-bold text-sm">
              <Code2 className="w-4 h-4 text-[#6D28D9]" />
              Copyable curl Request
            </div>
            <p className="text-xs text-[#6B7488] mt-1">
              macOS/Linux curl format. On Windows, use the PowerShell starter request from the Tenant Ready panel.
            </p>
          </div>
          <button
            onClick={() => copy("curl", curlCommand)}
            className="inline-flex items-center justify-center gap-2 px-3 py-2 rounded-[10px] bg-[#6D28D9] hover:bg-[#7C3AED] text-xs font-semibold text-white"
          >
            {copied === "curl" ? <Check className="w-4 h-4" /> : <Clipboard className="w-4 h-4" />}
            Copy curl
          </button>
        </div>
        <pre className="p-5 overflow-x-auto text-xs text-[#0E1726] bg-[#F5F7FA]">
          <code>{curlCommand}</code>
        </pre>
      </section>

      <section className="rounded-[20px] bg-white border border-[#E6E9F0] overflow-hidden shadow-[0_1px_2px_rgba(11,31,63,.05),0_12px_30px_-12px_rgba(11,31,63,.18)]">
        <div className="px-5 py-4 border-b border-[#E6E9F0] flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div>
            <div className="flex items-center gap-2 text-[#0E1726] font-bold text-sm">
              <Code2 className="w-4 h-4 text-[#6D28D9]" />
              Python SDK Request
            </div>
            <p className="text-xs text-[#6B7488] mt-1">
              Install-free helper from <code>sdk/python/authclaw_lite.py</code>.
            </p>
          </div>
          <button
            onClick={() => copy("python-sdk", pythonSdkSnippet)}
            className="inline-flex items-center justify-center gap-2 px-3 py-2 rounded-[10px] bg-[#6D28D9] hover:bg-[#7C3AED] text-xs font-semibold text-white"
          >
            {copied === "python-sdk" ? <Check className="w-4 h-4" /> : <Clipboard className="w-4 h-4" />}
            Copy Python
          </button>
        </div>
        <pre className="p-5 overflow-x-auto text-xs text-[#0E1726] bg-[#F5F7FA]">
          <code>{pythonSdkSnippet}</code>
        </pre>
      </section>

      <section className="rounded-[20px] bg-white border border-[#E6E9F0] overflow-hidden shadow-[0_1px_2px_rgba(11,31,63,.05),0_12px_30px_-12px_rgba(11,31,63,.18)]">
        <div className="px-5 py-4 border-b border-[#E6E9F0] flex items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2 text-[#0E1726] font-bold text-sm">
              <AlertTriangle className="w-4 h-4 text-amber-400" />
              HITL Approval Queue
            </div>
            <p className="text-xs text-[#6B7488] mt-1">
              High-risk policy matches wait here. If no one approves within 30 minutes, the gateway blocks the request.
            </p>
          </div>
          <button
            onClick={() => void fetchApprovals()}
            className="px-3 py-2 rounded-[10px] bg-[#F5F7FA] hover:bg-[#F1ECFE] text-xs font-semibold text-[#475069] border border-[#E6E9F0]"
          >
            Refresh
          </button>
        </div>

        {approvalError && (
          <div className="m-5 rounded-lg border border-red-500/20 bg-red-500/10 p-3 text-xs text-red-700">
            {approvalError}
          </div>
        )}

        {pendingApprovals.length === 0 ? (
          <div className="p-5 text-xs text-[#6B7488]">No pending gateway approvals.</div>
        ) : (
          <div className="divide-y divide-[#E6E9F0]">
            {pendingApprovals.map((approval) => (
              <div key={approval.id} className="p-5 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-bold text-[#0E1726]">
                      {approval.action_payload.rule_name || "Custom policy match"}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/20 text-[10px] font-bold uppercase text-amber-300">
                      {approval.action_payload.severity || "high"}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-[#F5F7FA] text-[10px] font-semibold text-[#475069] border border-[#E6E9F0]">
                      {approval.action_payload.provider || "provider"} / {approval.action_payload.model || "model"}
                    </span>
                  </div>
                  <p className="text-xs text-[#475069] mt-2">
                    {approval.action_payload.reason || approval.action_description}
                  </p>
                  <p className="text-[10px] text-[#6B7488] mt-1">
                    Request {approval.action_payload.request_id || approval.action_id} expires {new Date(approval.expires_at).toLocaleTimeString()}
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => void decideApproval(approval.id, "reject")}
                    disabled={approvalBusy === approval.id}
                    className="px-3 py-2 rounded-[10px] bg-red-500/10 hover:bg-red-500/20 border border-red-500/20 text-xs font-semibold text-red-700 disabled:opacity-50"
                  >
                    Reject
                  </button>
                  <button
                    onClick={() => handleGatewayApproveClick(approval)}
                    disabled={approvalBusy === approval.id}
                    className="px-3 py-2 rounded-[10px] bg-emerald-600 hover:bg-emerald-500 text-xs font-semibold text-white disabled:opacity-50"
                  >
                    Approve Passage
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="grid grid-cols-1 md:grid-cols-4 gap-3">
        {[
          "Tenant key validated",
          "PII/PHI redaction applied",
          "Policy allow/block decision recorded",
          "Audit evidence emitted",
        ].map((item) => (
          <div key={item} className="flex items-center gap-2 rounded-lg border border-[#E6E9F0] bg-white px-4 py-3">
            <Play className="w-3.5 h-3.5 text-emerald-400" />
            <span className="text-xs font-medium text-[#475069]">{item}</span>
          </div>
        ))}
      </section>

      {/* Gateway HITL MFA Challenge Modal */}
      {gatewayMfaTarget && (
        <MfaChallengeModal
          code={gatewayTotpCode}
          setCode={setGatewayTotpCode}
          busy={gatewayMfaBusy}
          error={gatewayMfaError}
          onClose={() => setGatewayMfaTarget(null)}
          onSubmit={handleGatewayMfaSubmit}
          accentClass="text-emerald-400"
          description="Confirm your administrator identity before allowing this gateway request to pass. Enter the 6-digit TOTP code from your authenticator app (or a backup recovery code)."
          submitLabel="Authorize Passage"
        />
      )}
    </div>
  );
}
