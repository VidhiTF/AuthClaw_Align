"use client";

import { CheckCircle2, Loader2, PlusCircle, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { jsonRequest, responseJsonOr } from "@/lib/client-fetch";
import { getErrorMessage } from "@/lib/errors";
import { formatDateTime } from "@/lib/ui-format";

type Tenant = {
  id: string;
  name: string;
  tier: string;
  status: string;
  created_at: string;
  updated_at: string;
};

export default function TenantCreateClient() {
  const [name, setName] = useState("");
  const [tier, setTier] = useState("starter");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [createdTenant, setCreatedTenant] = useState<Tenant | null>(null);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setCreatedTenant(null);
    try {
      const response = await fetch("/api/tenants", jsonRequest("POST", { name, tier }));
      const body = await responseJsonOr<Tenant | { detail?: string; error?: string }>(response, {});
      if (!response.ok) {
        throw new Error("detail" in body && body.detail ? body.detail : "error" in body && body.error ? body.error : "Failed to create tenant");
      }
      setCreatedTenant(body as Tenant);
      setName("");
      setTier("starter");
    } catch (requestError: unknown) {
      setError(getErrorMessage(requestError, "Failed to create tenant"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <div>
        <div className="mb-2 flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-[#6D28D9]">
          <ShieldCheck className="h-4 w-4" />
          Platform provisioning
        </div>
        <h1 className="text-3xl font-extrabold tracking-tight text-[#0E1726]">New Tenant</h1>
        <p className="mt-2 max-w-3xl text-sm text-[#475069]">
          Create customer tenants after intake review and approval.
        </p>
      </div>

      <section className="rounded-[20px] border border-[#E6E9F0] bg-white p-6 shadow-[0_1px_2px_rgba(11,31,63,.05),0_12px_30px_-12px_rgba(11,31,63,.18)]">
        <form onSubmit={submit} className="space-y-5">
          <div>
            <label htmlFor="tenant-name" className="block text-xs font-bold uppercase tracking-wider text-[#6B7488]">
              Tenant name
            </label>
            <input
              id="tenant-name"
              value={name}
              onChange={(event) => setName(event.target.value)}
              required
              minLength={1}
              maxLength={255}
              className="mt-2 w-full rounded-lg border border-[#E6E9F0] bg-white px-3 py-2 text-sm text-[#0E1726] outline-none transition focus:border-[#6D28D9]"
            />
          </div>
          <div>
            <label htmlFor="tenant-tier" className="block text-xs font-bold uppercase tracking-wider text-[#6B7488]">
              Tier
            </label>
            <select
              id="tenant-tier"
              value={tier}
              onChange={(event) => setTier(event.target.value)}
              className="mt-2 w-full rounded-lg border border-[#E6E9F0] bg-white px-3 py-2 text-sm text-[#0E1726] outline-none transition focus:border-[#6D28D9]"
            >
              <option value="starter">Starter</option>
              <option value="pro">Pro</option>
              <option value="enterprise">Enterprise</option>
            </select>
          </div>

          {error && <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</div>}

          <button
            type="submit"
            disabled={busy}
            className="inline-flex items-center justify-center gap-2 rounded-lg bg-[#6D28D9] px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-[#7C3AED] disabled:opacity-50"
          >
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <PlusCircle className="h-4 w-4" />}
            Create tenant
          </button>
        </form>
      </section>

      {createdTenant && (
        <section className="rounded-[20px] border border-emerald-200 bg-emerald-50 p-5 text-emerald-900">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="h-5 w-5" />
            <h2 className="text-sm font-bold">Tenant created</h2>
          </div>
          <p className="mt-3 text-sm font-semibold">{createdTenant.name}</p>
          <p className="mt-1 font-mono text-xs">
            {createdTenant.id} · {createdTenant.tier} · {createdTenant.status} · {formatDateTime(createdTenant.created_at)}
          </p>
        </section>
      )}
    </div>
  );
}
