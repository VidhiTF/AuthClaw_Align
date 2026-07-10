"use client";

import { useState } from 'react';
import { CheckCircle, KeyRound, PauseCircle, PlayCircle, Plus, Trash2, XCircle } from 'lucide-react';
import { toast } from 'sonner';
import { apiClient } from '@/lib/api-client';
import { useCreateProvider, useDeleteProvider, useProviders, useUpdateProvider } from '@/hooks/use-data';
import { Card, CardContent, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { TableSkeleton } from '@/components/shared/loaders';

type Provider = {
  id: string;
  name: string;
  type?: string;
  provider_type?: string;
  config?: Record<string, unknown>;
  is_active: boolean;
  created_at: string;
};

export default function GatewayProvidersPage() {
  const { data = [], isLoading } = useProviders();
  const createProvider = useCreateProvider();
  const deleteProvider = useDeleteProvider();
  const updateProvider = useUpdateProvider();
  const providers = data as Provider[];
  const [form, setForm] = useState({
    name: 'Groq Default',
    type: 'groq',
    api_key: '',
    base_url: 'https://api.groq.com/openai/v1',
    model: 'llama-3.1-8b-instant',
  });
  const [validation, setValidation] = useState<Record<string, boolean>>({});

  const submit = async () => {
    if (!form.name.trim() || !form.api_key.trim()) {
      toast.error('Provider name and credential are required');
      return;
    }
    try {
      await createProvider.mutateAsync({
        name: form.name.trim(),
        type: form.type,
        api_key: form.api_key,
        config: { base_url: form.base_url, model: form.model },
      });
      setForm((current) => ({ ...current, api_key: '' }));
      toast.success('Provider credential saved');
    } catch {
      toast.error('Provider could not be saved');
    }
  };

  const validate = async (id: string) => {
    try {
      const response = await apiClient.post(`/gateway/providers/${id}/validate`);
      const valid = Boolean(response.data?.valid);
      setValidation((current) => ({ ...current, [id]: valid }));
      const mode = response.data?.validation_mode === 'live' ? 'live check' : 'metadata check';
      toast[valid ? 'success' : 'warning'](valid ? `Provider credential validated (${mode})` : 'Provider validation failed');
    } catch {
      setValidation((current) => ({ ...current, [id]: false }));
      toast.error('Provider validation failed');
    }
  };

  return (
    <div className="space-y-6 max-w-[1500px] mx-auto pb-10">
      <div>
        <h2 className="text-2xl font-bold text-neutral-100">Gateway Providers</h2>
        <p className="text-sm text-neutral-400 mt-1">Store upstream credentials in the secure credential flow and expose metadata only.</p>
      </div>

      <Card className="glass-card">
        <div className="p-4 border-b border-white/5 bg-black/20 flex items-center gap-2">
          <Plus className="w-4 h-4 text-blue-400" />
          <CardTitle className="text-base text-neutral-100">Add Groq Provider</CardTitle>
        </div>
        <CardContent className="p-4 grid grid-cols-1 md:grid-cols-5 gap-3">
          <input className="bg-black/30 border border-white/10 rounded-lg px-3 py-2 text-sm text-neutral-100" value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="Provider name" />
          <select className="bg-black/30 border border-white/10 rounded-lg px-3 py-2 text-sm text-neutral-100" value={form.type} onChange={(event) => setForm({ ...form, type: event.target.value })}>
            <option value="groq">Groq</option>
            <option value="openai">OpenAI-compatible</option>
          </select>
          <input className="bg-black/30 border border-white/10 rounded-lg px-3 py-2 text-sm text-neutral-100" value={form.base_url} onChange={(event) => setForm({ ...form, base_url: event.target.value })} placeholder="Base URL" />
          <input className="bg-black/30 border border-white/10 rounded-lg px-3 py-2 text-sm text-neutral-100" value={form.model} onChange={(event) => setForm({ ...form, model: event.target.value })} placeholder="Model" />
          <input type="password" className="bg-black/30 border border-white/10 rounded-lg px-3 py-2 text-sm text-neutral-100" value={form.api_key} onChange={(event) => setForm({ ...form, api_key: event.target.value })} placeholder="Provider API key" />
          <button onClick={submit} disabled={createProvider.isPending} className="md:col-span-5 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:bg-blue-900 text-white px-4 py-2 text-sm font-medium">Save Provider</button>
        </CardContent>
      </Card>

      <Card className="glass-card overflow-hidden">
        <div className="p-4 border-b border-white/5 bg-black/20 flex items-center gap-2">
          <KeyRound className="w-4 h-4 text-emerald-400" />
          <CardTitle className="text-base text-neutral-100">Provider Metadata</CardTitle>
        </div>
        {isLoading ? (
          <div className="p-4"><TableSkeleton columns={5} rows={4} /></div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-neutral-900/80 border-b border-white/5">
              <tr>
                {['Name', 'Type', 'Model', 'Status', 'Actions'].map((header) => <th key={header} className="text-left p-4 text-xs uppercase tracking-wider text-neutral-400">{header}</th>)}
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {providers.map((provider) => (
                <tr key={provider.id}>
                  <td className="p-4 text-neutral-100">{provider.name}</td>
                  <td className="p-4 text-neutral-300">{provider.type || provider.provider_type}</td>
                  <td className="p-4 text-neutral-300 font-mono text-xs">{String(provider.config?.model || '-')}</td>
                  <td className="p-4">
                    <Badge variant="outline" className={provider.is_active ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 'bg-neutral-500/10 text-neutral-400 border-neutral-700'}>
                      {provider.is_active ? 'Active' : 'Disabled'}
                    </Badge>
                  </td>
                  <td className="p-4 flex gap-2">
                    <button onClick={() => validate(provider.id)} className="p-2 rounded-lg border border-white/10 text-neutral-300 hover:text-white" title="Validate credential">
                      {validation[provider.id] ? <CheckCircle className="w-4 h-4 text-emerald-400" /> : <XCircle className="w-4 h-4" />}
                    </button>
                    <button
                      onClick={() => updateProvider.mutate({ id: provider.id, data: { is_active: !provider.is_active } })}
                      className="p-2 rounded-lg border border-white/10 text-neutral-300 hover:text-white"
                      title={provider.is_active ? 'Disable provider' : 'Enable provider'}
                    >
                      {provider.is_active ? <PauseCircle className="w-4 h-4" /> : <PlayCircle className="w-4 h-4" />}
                    </button>
                    <button onClick={() => deleteProvider.mutate(provider.id)} className="p-2 rounded-lg border border-red-500/20 text-red-300 hover:text-red-200" title="Delete provider">
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
