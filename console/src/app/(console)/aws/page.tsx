"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Cloud,
  GitPullRequest,
  KeyRound,
  Loader2,
  RefreshCw,
  ShieldCheck,
  Trash2,
  XCircle,
} from "lucide-react";
import { apiErrorMessage, getErrorMessage } from "@/lib/errors";
import { jsonRequest } from "@/lib/client-fetch";

type Provider = "aws" | "github" | "gcp";

interface CatalogItem {
  provider: Provider;
  display_name: string;
  auth_type: string;
  fields: string[];
  optional_fields: string[];
  actions: string[];
  oauth_url?: string | null;
}

interface CloudConnector {
  id: string;
  provider: Provider;
  display_name: string;
  auth_type: string;
  status: string;
  last_verified_at?: string | null;
  last_error?: string | null;
  created_at?: string | null;
  metadata: Record<string, string | number | boolean | null | undefined>;
}

interface CloudListResponse {
  catalog: CatalogItem[];
  connectors: CloudConnector[];
}

const providerHints: Record<Provider, string> = {
  aws: "Use a least-privilege IAM access key. S3 inventory/remediation and IAM scan actions only need scoped permissions.",
  github: "Use a fine-grained PAT or GitHub App token with repo metadata, security events, and pull request write access.",
  gcp: "Paste a service-account JSON key with Cloud Asset, IAM read, and the narrow remediation permission you need.",
};

const defaultForms: Record<Provider, Record<string, string>> = {
  aws: { access_key_id: "", secret_access_key: "", region: "us-east-1", bucket: "" },
  github: { token: "", owner: "", repo: "" },
  gcp: { service_account_json: "", project_id: "" },
};

function statusClass(status: string) {
  if (status === "connected") return "border-emerald-500/20 bg-emerald-500/10 text-emerald-500";
  if (status === "error") return "border-red-500/20 bg-red-500/10 text-red-500";
  return "border-[#E6E9F0] bg-[#F5F7FA] text-[#6B7488]";
}

function StatusIcon({ status }: { status: string }) {
  if (status === "connected") return <CheckCircle2 className="h-4 w-4 text-emerald-500" />;
  if (status === "error") return <XCircle className="h-4 w-4 text-red-500" />;
  return <AlertTriangle className="h-4 w-4 text-amber-500" />;
}

export default function CloudPage() {
  const [catalog, setCatalog] = useState<CatalogItem[]>([]);
  const [connectors, setConnectors] = useState<CloudConnector[]>([]);
  const [selectedProvider, setSelectedProvider] = useState<Provider>("aws");
  const [selectedConnectorId, setSelectedConnectorId] = useState("");
  const [action, setAction] = useState("inventory");
  const [form, setForm] = useState<Record<string, string>>(defaultForms.aws);
  const [displayName, setDisplayName] = useState("Production cloud");
  const [actionPayload, setActionPayload] = useState("{}");
  const [actionTotp, setActionTotp] = useState("");
  const [actionResult, setActionResult] = useState<unknown>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [running, setRunning] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/cloud");
      const data = await res.json();
      if (!res.ok) throw new Error(apiErrorMessage(data, "Failed to load cloud connectors"));
      const payload = data as CloudListResponse;
      setCatalog(payload.catalog || []);
      setConnectors(payload.connectors || []);
      setSelectedConnectorId((current) => current || payload.connectors?.[0]?.id || "");
    } catch (err) {
      setError(getErrorMessage(err, "Failed to load cloud connectors"));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void load();
    }, 0);
    return () => window.clearTimeout(timer);
  }, [load]);

  const selectedCatalog = useMemo(
    () => catalog.find((item) => item.provider === selectedProvider),
    [catalog, selectedProvider]
  );
  const selectedConnector = useMemo(
    () => connectors.find((item) => item.id === selectedConnectorId) || connectors[0],
    [connectors, selectedConnectorId]
  );
  const actions = useMemo(
    () => selectedConnector
      ? catalog.find((item) => item.provider === selectedConnector.provider)?.actions || []
      : selectedCatalog?.actions || [],
    [catalog, selectedCatalog, selectedConnector]
  );
  const activeAction = actions.includes(action) ? action : actions[0] || "inventory";
  const actionRequiresMfa = activeAction === "remediate" || activeAction === "pr-remediation";

  const updateProvider = (provider: Provider) => {
    setSelectedProvider(provider);
    setForm(defaultForms[provider]);
    setDisplayName(`${provider.toUpperCase()} connector`);
    setMessage(null);
    setError(null);
  };

  const saveConnector = async (event: React.FormEvent) => {
    event.preventDefault();
    setSaving(true);
    setMessage(null);
    setError(null);
    try {
      const metadata: Record<string, string> = {};
      for (const field of selectedCatalog?.optional_fields || []) {
        if (form[field]) metadata[field] = form[field];
      }
      const res = await fetch("/api/cloud", jsonRequest("POST", {
        provider: selectedProvider,
        display_name: displayName,
        credentials: form,
        metadata,
      }));
      const data = await res.json();
      if (!res.ok) throw new Error(apiErrorMessage(data, "Failed to connect provider"));
      setMessage(`${data.display_name} connected. Raw credentials were encrypted and are no longer visible.`);
      setForm(defaultForms[selectedProvider]);
      await load();
      setSelectedConnectorId(data.id);
    } catch (err) {
      setError(getErrorMessage(err, "Failed to connect provider"));
    } finally {
      setSaving(false);
    }
  };

  const verifyConnector = async (id: string) => {
    setMessage(null);
    setError(null);
    try {
      const res = await fetch(`/api/cloud/${id}/verify`, { method: "POST" });
      const data = await res.json();
      if (!res.ok) throw new Error(apiErrorMessage(data, "Verification failed"));
      setMessage(data.result?.ok ? "Connector verified." : data.result?.error || "Verification failed");
      await load();
    } catch (err) {
      setError(getErrorMessage(err, "Verification failed"));
    }
  };

  const revokeConnector = async (id: string) => {
    if (!confirm("Revoke this cloud connector? Stored credentials will no longer be usable.")) return;
    setError(null);
    try {
      const res = await fetch(`/api/cloud/${id}`, { method: "DELETE" });
      if (!res.ok) throw new Error("Failed to revoke connector");
      setSelectedConnectorId("");
      await load();
    } catch (err) {
      setError(getErrorMessage(err, "Failed to revoke connector"));
    }
  };

  const runAction = async () => {
    if (!selectedConnector) return;
    setRunning(true);
    setActionResult(null);
    setError(null);
    try {
      const payload = actionPayload.trim() ? JSON.parse(actionPayload) : {};
      const res = await fetch(`/api/cloud/${selectedConnector.id}/actions/${activeAction}`, jsonRequest("POST", {
        payload,
        totp_code: actionRequiresMfa ? actionTotp : undefined,
      }));
      const data = await res.json();
      if (!res.ok) throw new Error(apiErrorMessage(data, "Cloud action failed"));
      setActionResult(data);
      setActionTotp("");
    } catch (err) {
      setError(getErrorMessage(err, "Cloud action failed"));
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-3xl font-extrabold tracking-tight text-[#0E1726]">Cloud Connectors</h1>
          <p className="mt-1 text-sm text-[#6B7488]">Connect AWS, GitHub, and Google Cloud, then run inventory, security, and remediation actions.</p>
        </div>
        <button onClick={load} className="inline-flex items-center gap-2 rounded-lg border border-[#E6E9F0] bg-white px-3 py-2 text-xs font-semibold text-[#475069] hover:bg-[#F5F7FA]">
          <RefreshCw className="h-4 w-4" />
          Refresh
        </button>
      </div>

      {(message || error) && (
        <div className={`rounded-lg border p-3 text-xs ${error ? "border-red-500/20 bg-red-500/10 text-red-600" : "border-emerald-500/20 bg-emerald-500/10 text-emerald-700"}`}>
          {error || message}
        </div>
      )}

      <div className="grid gap-6 xl:grid-cols-[minmax(0,0.85fr)_minmax(0,1.15fr)]">
        <form onSubmit={saveConnector} className="rounded-[8px] border border-[#E6E9F0] bg-white p-5 shadow-xl">
          <div className="mb-5 flex items-start justify-between gap-4">
            <div>
              <h2 className="flex items-center gap-2 text-sm font-bold text-[#0E1726]">
                <KeyRound className="h-4 w-4 text-indigo-500" />
                Direct Cloud Login
              </h2>
              <p className="mt-1 text-xs leading-relaxed text-[#6B7488]">{providerHints[selectedProvider]}</p>
            </div>
            <span className="rounded-full border border-emerald-500/20 bg-emerald-500/10 px-2 py-1 text-[10px] font-bold uppercase text-emerald-600">
              Encrypted
            </span>
          </div>

          <div className="mb-4 grid grid-cols-3 gap-2">
            {(["aws", "github", "gcp"] as Provider[]).map((provider) => (
              <button
                key={provider}
                type="button"
                onClick={() => updateProvider(provider)}
                className={`rounded-lg border px-3 py-2 text-xs font-bold uppercase ${selectedProvider === provider ? "border-indigo-500 bg-indigo-500/10 text-indigo-600" : "border-[#E6E9F0] bg-[#F5F7FA] text-[#6B7488]"}`}
              >
                {provider}
              </button>
            ))}
          </div>

          <label className="mb-1.5 block text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">Display Name</label>
          <input value={displayName} onChange={(event) => setDisplayName(event.target.value)} className="mb-4 w-full rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] px-3 py-2 text-xs text-[#0E1726] focus:border-indigo-500/80 focus:outline-none" />

          <div className="space-y-3">
            {[...(selectedCatalog?.fields || []), ...(selectedCatalog?.optional_fields || [])].map((field) => (
              <div key={field}>
                <label className="mb-1.5 block text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">
                  {field.replace(/_/g, " ")}
                  {selectedCatalog?.optional_fields.includes(field) ? "" : " *"}
                </label>
                {field.includes("json") ? (
                  <textarea
                    value={form[field] || ""}
                    onChange={(event) => setForm((current) => ({ ...current, [field]: event.target.value }))}
                    rows={6}
                    className="w-full rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] px-3 py-2 font-mono text-xs text-[#0E1726] focus:border-indigo-500/80 focus:outline-none"
                  />
                ) : (
                  <input
                    type={field.includes("secret") || field === "token" ? "password" : "text"}
                    value={form[field] || ""}
                    onChange={(event) => setForm((current) => ({ ...current, [field]: event.target.value }))}
                    className="w-full rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] px-3 py-2 text-xs text-[#0E1726] focus:border-indigo-500/80 focus:outline-none"
                  />
                )}
              </div>
            ))}
          </div>

          <div className="mt-4 rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] p-3 text-[10px] leading-relaxed text-[#6B7488]">
            Secrets are envelope-encrypted in the backend and never returned to the browser after save. Use cloud-native least-privilege credentials and rotate them regularly.
          </div>

          <button disabled={saving} className="mt-5 inline-flex w-full items-center justify-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-xs font-semibold text-white hover:bg-indigo-500 disabled:opacity-50">
            {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
            {saving ? "Connecting..." : "Connect Provider"}
          </button>
        </form>

        <div className="space-y-6">
          <div className="rounded-[8px] border border-[#E6E9F0] bg-white shadow-xl">
            <div className="flex items-center justify-between border-b border-[#E6E9F0] px-5 py-4">
              <div>
                <h2 className="text-sm font-bold text-[#0E1726]">Connected Clouds</h2>
                <p className="mt-1 text-xs text-[#6B7488]">{connectors.length} active connector{connectors.length === 1 ? "" : "s"}</p>
              </div>
              {loading && <Loader2 className="h-4 w-4 animate-spin text-[#6B7488]" />}
            </div>

            {connectors.length === 0 ? (
              <div className="p-8 text-center text-xs text-[#6B7488]">
                <Cloud className="mx-auto mb-3 h-9 w-9 text-[#A8B0C0]" />
                No cloud connectors yet.
              </div>
            ) : (
              <div className="divide-y divide-[#E6E9F0]">
                {connectors.map((connector) => (
                  <button
                    key={connector.id}
                    type="button"
                    onClick={() => setSelectedConnectorId(connector.id)}
                    className={`w-full px-5 py-4 text-left transition hover:bg-[#F5F7FA] ${selectedConnector?.id === connector.id ? "bg-[#F5F7FA]" : "bg-white"}`}
                  >
                    <div className="flex items-start justify-between gap-4">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <StatusIcon status={connector.status} />
                          <span className="font-semibold text-[#0E1726]">{connector.display_name}</span>
                          <span className="font-mono text-[10px] uppercase text-[#6B7488]">{connector.provider}</span>
                        </div>
                        <div className="mt-2 flex flex-wrap gap-2 text-[10px] text-[#6B7488]">
                          {Object.entries(connector.metadata || {}).slice(0, 4).map(([key, value]) => (
                            <span key={key} className="rounded border border-[#E6E9F0] bg-white px-2 py-1 font-mono">
                              {key}: {String(value)}
                            </span>
                          ))}
                        </div>
                        {connector.last_error && <p className="mt-2 text-xs text-red-500">{connector.last_error}</p>}
                      </div>
                      <span className={`shrink-0 rounded-full border px-2 py-1 text-[10px] font-bold uppercase ${statusClass(connector.status)}`}>
                        {connector.status}
                      </span>
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>

          {selectedConnector && (
            <div className="rounded-[8px] border border-[#E6E9F0] bg-white p-5 shadow-xl">
              <div className="mb-4 flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                <div>
                  <h2 className="text-sm font-bold text-[#0E1726]">Cloud Actions</h2>
                  <p className="mt-1 text-xs text-[#6B7488]">Run provider actions through the audited connector API.</p>
                </div>
                <div className="flex gap-2">
                  <button onClick={() => verifyConnector(selectedConnector.id)} className="inline-flex items-center gap-1 rounded-lg border border-[#E6E9F0] px-3 py-2 text-xs font-semibold text-[#475069] hover:bg-[#F5F7FA]">
                    <RefreshCw className="h-3.5 w-3.5" />
                    Verify
                  </button>
                  <button onClick={() => revokeConnector(selectedConnector.id)} className="inline-flex items-center gap-1 rounded-lg border border-red-500/20 px-3 py-2 text-xs font-semibold text-red-500 hover:bg-red-500/10">
                    <Trash2 className="h-3.5 w-3.5" />
                    Revoke
                  </button>
                </div>
              </div>

              <div className="grid gap-4 md:grid-cols-[220px_minmax(0,1fr)]">
                <div>
                  <label className="mb-1.5 block text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">Action</label>
                  <select value={activeAction} onChange={(event) => setAction(event.target.value)} className="w-full rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] px-3 py-2 text-xs text-[#0E1726] focus:border-indigo-500/80 focus:outline-none">
                    {actions.map((item) => <option key={item} value={item}>{item}</option>)}
                  </select>
                </div>
                <div>
                  <label className="mb-1.5 block text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">Payload JSON</label>
                  <textarea value={actionPayload} onChange={(event) => setActionPayload(event.target.value)} rows={4} className="w-full rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] px-3 py-2 font-mono text-xs text-[#0E1726] focus:border-indigo-500/80 focus:outline-none" />
                </div>
              </div>

              {actionRequiresMfa && (
                <div className="mt-4 grid gap-4 md:grid-cols-[220px_minmax(0,1fr)]">
                  <div>
                    <label className="mb-1.5 block text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">Fresh MFA Code</label>
                    <input
                      type="password"
                      value={actionTotp}
                      onChange={(event) => setActionTotp(event.target.value)}
                      className="w-full rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] px-3 py-2 text-xs text-[#0E1726] focus:border-indigo-500/80 focus:outline-none"
                    />
                  </div>
                  <div className="rounded-lg border border-amber-500/20 bg-amber-500/10 p-3 text-[10px] leading-relaxed text-amber-700">
                    External mutations use a fresh TOTP or backup code and run through the audited connector API.
                  </div>
                </div>
              )}

              <button onClick={runAction} disabled={running} className="mt-4 inline-flex items-center gap-2 rounded-lg bg-emerald-600 px-4 py-2 text-xs font-semibold text-white hover:bg-emerald-500 disabled:opacity-50">
                {running ? <Loader2 className="h-4 w-4 animate-spin" /> : <GitPullRequest className="h-4 w-4" />}
                Run Action
              </button>

              {actionResult != null && (
                <pre className="mt-4 max-h-[420px] overflow-auto rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] p-4 text-xs text-[#475069]">
                  {JSON.stringify(actionResult, null, 2)}
                </pre>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
