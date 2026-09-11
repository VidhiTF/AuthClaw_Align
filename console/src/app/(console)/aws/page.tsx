"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Cloud,
  KeyRound,
  Link2,
  Loader2,
  MoreVertical,
  Play,
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

function ProviderMark({ provider }: { provider: Provider }) {
  if (provider === "github") return <span className="flex h-7 w-7 items-center justify-center rounded-full bg-black text-[9px] font-black text-white">GH</span>;
  if (provider === "gcp") return <Cloud className="h-6 w-6 text-[#4285F4]" />;
  return <span className="text-sm font-black tracking-tight text-[#F59E0B]">aws</span>;
}

function connectorDate(value?: string | null) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
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
  const credentialFields = selectedCatalog
    ? [...selectedCatalog.fields, ...selectedCatalog.optional_fields]
    : Object.keys(defaultForms[selectedProvider]);
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
    <div className="ac-page ac-page-cloud mx-auto max-w-none space-y-5">
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-3xl font-extrabold tracking-tight text-[#0E1726]">Cloud Connectors</h1>
          <p className="mt-1 text-sm text-[#6B7488]">Connect and manage your cloud providers for secure AI governance.</p>
        </div>
        <div className="text-right">
          <button onClick={load} className="inline-flex items-center gap-2 rounded-md border border-[#D7DCE5] bg-white px-4 py-2 text-xs font-semibold text-[#263244] hover:bg-[#F5F7FA]">
            <RefreshCw className="h-4 w-4" /> Refresh
          </button>
          <p className="mt-1 text-[10px] text-[#6B7488]">Last refreshed just now</p>
        </div>
      </div>

      {(message || error) && (
        <div className={`rounded-lg border p-3 text-xs ${error ? "border-red-500/20 bg-red-500/10 text-red-600" : "border-emerald-500/20 bg-emerald-500/10 text-emerald-700"}`}>
          {error || message}
        </div>
      )}

      <div className="ac-cloud-workspace grid gap-4 xl:grid-cols-[minmax(19rem,0.78fr)_minmax(0,1.65fr)]">
        <form onSubmit={saveConnector} className="ac-cloud-setup rounded-md border border-[#DCE1E9] bg-white p-4 shadow-none">
          <div className="mb-4">
            <div>
              <h2 className="text-base font-bold text-[#0E1726]">Direct Cloud Login</h2>
              <p className="mt-0.5 text-xs text-[#6B7488]">Connect a cloud provider using your real credentials.</p>
            </div>
          </div>

          <label className="mb-2 block text-xs font-semibold text-[#263244]">Provider</label>
          <div className="ac-provider-picker mb-4 grid grid-cols-3 gap-2">
            {(["aws", "github", "gcp"] as Provider[]).map((provider) => (
              <button
                key={provider}
                type="button"
                onClick={() => updateProvider(provider)}
                className={`flex min-h-20 flex-col items-center justify-center gap-1 rounded-md border bg-white px-2 py-2 text-xs font-semibold ${selectedProvider === provider ? "border-[#6D28D9] text-[#6D28D9] ring-1 ring-[#6D28D9]" : "border-[#DCE1E9] text-[#263244] hover:border-[#A78BFA]"}`}
              >
                <ProviderMark provider={provider} />
                <span>{provider === "gcp" ? "GCP" : provider === "github" ? "GitHub" : "AWS"}</span>
                <span className={`h-3.5 w-3.5 rounded-full border ${selectedProvider === provider ? "border-[4px] border-[#6D28D9]" : "border-[#8A94A8]"}`} />
              </button>
            ))}
          </div>

          <label className="mb-1.5 block text-xs font-semibold text-[#263244]">Display name</label>
          <input placeholder="e.g. Production AWS" value={displayName} onChange={(event) => setDisplayName(event.target.value)} className="mb-4 h-9 w-full rounded-md border border-[#D7DCE5] bg-white px-3 text-xs text-[#0E1726] focus:border-indigo-500/80 focus:outline-none" />

          <p className="mb-2 text-xs font-semibold text-[#263244]">Credentials</p>

          <div className="space-y-3">
            {credentialFields.map((field) => (
              <div key={field}>
                <label className="mb-1.5 block text-xs font-medium text-[#263244]">
                  {field.replace(/_/g, " ")}
                  {selectedCatalog?.optional_fields.includes(field) ? "" : " *"}
                </label>
                {field.includes("json") ? (
                  <textarea
                    value={form[field] || ""}
                    onChange={(event) => setForm((current) => ({ ...current, [field]: event.target.value }))}
                    rows={6}
                    className="w-full rounded-md border border-[#D7DCE5] bg-white px-3 py-2 font-mono text-xs text-[#0E1726] focus:border-indigo-500/80 focus:outline-none"
                  />
                ) : (
                  <input
                    type={field.includes("secret") || field === "token" ? "password" : "text"}
                    value={form[field] || ""}
                    onChange={(event) => setForm((current) => ({ ...current, [field]: event.target.value }))}
                    placeholder={field === "access_key_id" ? "AKIA..." : undefined}
                    className="h-9 w-full rounded-md border border-[#D7DCE5] bg-white px-3 text-xs text-[#0E1726] focus:border-indigo-500/80 focus:outline-none"
                  />
                )}
              </div>
            ))}
          </div>

          <div className="mt-4 flex gap-2 rounded-md bg-[#F3F7FF] p-3 text-[10px] leading-relaxed text-[#475069]">
            <KeyRound className="mt-0.5 h-4 w-4 shrink-0 text-[#2563EB]" />
            <span><strong className="block text-[#1D4ED8]">Your credentials are encrypted</strong>Credentials are encrypted at rest and never displayed after saving.</span>
          </div>

          <button disabled={saving} className="mt-4 inline-flex h-10 w-full items-center justify-center gap-2 rounded-md bg-[#6D28D9] px-4 text-xs font-semibold text-white hover:bg-[#5B21B6] disabled:opacity-50">
            {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Link2 className="h-4 w-4" />}
            {saving ? "Connecting..." : "Connect Provider"}
          </button>
          <p className="mt-3 text-[10px] leading-relaxed text-[#6B7488]">By connecting, you confirm you have the necessary permissions to access this cloud account.</p>
        </form>

        <div className="space-y-4">
          <section className="overflow-hidden rounded-md border border-[#DCE1E9] bg-white">
            <div className="flex items-start justify-between px-4 pb-3 pt-4">
              <div>
                <h2 className="text-base font-bold text-[#0E1726]">Connected Clouds</h2>
                <p className="mt-0.5 text-xs text-[#6B7488]">Select a connected provider to view details and perform actions.</p>
              </div>
              {loading && <Loader2 className="h-4 w-4 animate-spin text-[#6B7488]" />}
            </div>
            <div className="overflow-x-auto px-4 pb-4">
              <table className="w-full min-w-[680px] border-collapse text-left text-[11px]">
                <thead className="border border-[#E2E6ED] bg-[#F5F7FA] text-[9px] font-semibold text-[#475069]">
                  <tr><th className="px-3 py-2">Provider</th><th className="px-3 py-2">Display Name</th><th className="px-3 py-2">Status</th><th className="px-3 py-2">Connected At</th><th className="px-3 py-2">Last Used</th><th className="px-3 py-2 text-center">Actions</th></tr>
                </thead>
                <tbody>
                  {connectors.length === 0 ? (
                    <tr><td colSpan={6} className="border border-t-0 border-[#E2E6ED] px-3 py-8 text-center text-xs text-[#6B7488]">No cloud connectors yet. Add your first provider using the secure login form.</td></tr>
                  ) : connectors.map((connector) => (
                    <tr key={connector.id} onClick={() => setSelectedConnectorId(connector.id)} className={`cursor-pointer border-x border-b border-[#E2E6ED] ${selectedConnector?.id === connector.id ? "bg-[#F4ECFF] shadow-[inset_3px_0_0_#6D28D9]" : "hover:bg-[#FAFAFC]"}`}>
                      <td className="px-3 py-2.5"><ProviderMark provider={connector.provider} /></td>
                      <td className="px-3 py-2.5 font-semibold text-[#172033]">{connector.display_name}</td>
                      <td className="px-3 py-2.5"><span className={`inline-flex items-center gap-1 rounded-full border px-2 py-1 text-[9px] font-semibold capitalize ${statusClass(connector.status)}`}><StatusIcon status={connector.status} />{connector.status}</span></td>
                      <td className="px-3 py-2.5 text-[#475069]">{connectorDate(connector.created_at)}</td>
                      <td className="px-3 py-2.5 text-[#475069]">{connectorDate(connector.last_verified_at)}</td>
                      <td className="px-3 py-2.5 text-center"><MoreVertical className="mx-auto h-4 w-4" /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <section className="rounded-md border border-[#DCE1E9] bg-white p-4">
            <div className="mb-4 flex items-start justify-between gap-4">
              <div><h2 className="text-base font-bold text-[#0E1726]">Cloud Actions</h2><p className="mt-0.5 text-xs text-[#6B7488]">Perform operational actions on the selected cloud provider.</p></div>
              <div className="flex items-center gap-4 rounded-md bg-[#F5F7FA] px-3 py-2 text-[10px]"><span className="font-medium text-[#263244]">All actions are audited</span><a href="/audit" className="font-semibold text-[#6D28D9]">View audit logs →</a></div>
            </div>
            <div className="grid gap-4 md:grid-cols-2">
              <div><label className="mb-1.5 block text-xs font-semibold">Action</label><select value={activeAction} onChange={(event) => setAction(event.target.value)} className="h-9 w-full rounded-md border border-[#D7DCE5] bg-white px-3 text-xs"><option value="inventory">Select an action</option>{actions.map((item) => <option key={item} value={item}>{item}</option>)}</select><p className="mt-1 text-[10px] text-[#6B7488]">Runs through the audited connector API.</p></div>
              <div><label className="mb-1.5 block text-xs font-semibold">Fresh MFA Code (optional)</label><input type="password" placeholder="Enter 6-digit code" value={actionTotp} onChange={(event) => setActionTotp(event.target.value)} className="h-9 w-full rounded-md border border-[#D7DCE5] bg-white px-3 text-xs"/><p className="mt-1 text-[10px] text-[#6B7488]">Required for protected mutation actions.</p></div>
            </div>
            <div className="mt-4"><label className="mb-1.5 block text-xs font-semibold">Payload (JSON)</label><textarea value={actionPayload} onChange={(event) => setActionPayload(event.target.value)} rows={7} className="w-full resize-none rounded-none border border-[#D7DCE5] bg-[#FBFCFE] p-4 font-mono text-xs leading-6 text-[#1D4ED8]" /></div>
            {actionResult != null && <pre className="mt-3 max-h-48 overflow-auto border border-[#D7DCE5] bg-[#F5F7FA] p-3 text-xs">{JSON.stringify(actionResult, null, 2)}</pre>}
            <div className="mt-4 flex flex-wrap items-center gap-3">
              <button onClick={() => selectedConnector && verifyConnector(selectedConnector.id)} disabled={!selectedConnector} className="inline-flex h-9 items-center gap-2 rounded-md border border-[#D7DCE5] px-4 text-xs font-semibold disabled:opacity-40"><ShieldCheck className="h-4 w-4"/>Verify Connection</button>
              <button onClick={() => selectedConnector && revokeConnector(selectedConnector.id)} disabled={!selectedConnector} className="inline-flex h-9 items-center gap-2 rounded-md border border-red-500 px-4 text-xs font-semibold text-red-600 disabled:opacity-40"><Trash2 className="h-4 w-4"/>Revoke Connection</button>
              <button onClick={runAction} disabled={running || !selectedConnector} className="ml-auto inline-flex h-9 items-center gap-2 rounded-md bg-[#6D28D9] px-5 text-xs font-semibold text-white disabled:opacity-40">{running ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}Run Action</button>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
