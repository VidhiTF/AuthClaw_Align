"use client";

import { useState } from 'react';
import { CheckCheck, Copy, Eye, EyeOff, KeyRound, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import { useApiKeys, useCreateApiKey, useRevokeApiKey } from '@/hooks/use-data';
import { Card, CardContent, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { TableSkeleton } from '@/components/shared/loaders';

type ApiKeyRecord = {
  id: string;
  name: string;
  key_prefix: string;
  scope?: string;
  is_active: boolean;
  expires_at?: string | null;
  last_used_at?: string | null;
  created_at: string;
};

type CreatedApiKey = {
  raw_key?: string;
  revoked_key_count?: number;
};

export default function GatewayApiKeysPage() {
  const { data, isLoading } = useApiKeys(0, 100);
  const createApiKey = useCreateApiKey();
  const revokeApiKey = useRevokeApiKey();
  const keys = (Array.isArray(data) ? data : data?.items || []) as ApiKeyRecord[];
  const [name, setName] = useState('Gateway agent key');
  const [generated, setGenerated] = useState<{ rawKey: string; visible: boolean } | null>(null);
  const [copied, setCopied] = useState(false);

  const create = async () => {
    const result = await createApiKey.mutateAsync({ name, scope: 'gateway_only' }) as CreatedApiKey;
    if (result.raw_key) {
      setGenerated({ rawKey: result.raw_key, visible: false });
      setName('Gateway agent key');
      toast.success('Gateway API key generated', {
        description: (result.revoked_key_count || 0) > 0 ? 'Previous active gateway key was revoked automatically.' : undefined,
      });
    }
  };

  const copy = async () => {
    if (!generated?.rawKey) return;
    await navigator.clipboard.writeText(generated.rawKey);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="space-y-6 max-w-[1400px] mx-auto pb-10">
      <div>
        <h2 className="text-2xl font-bold text-neutral-100">Gateway API Keys</h2>
        <p className="text-sm text-neutral-400 mt-1">Generate the tenant-scoped AuthClaw gateway key for agents and apps. Creating a new key revokes the previous active key.</p>
      </div>

      {generated && (
        <Card className="glass-card border-amber-500/20">
          <CardContent className="p-4 space-y-3">
            <div className="text-sm font-semibold text-amber-300">Copy this key now. It will not be shown again.</div>
            <div className="flex gap-2">
              <input readOnly type={generated.visible ? 'text' : 'password'} value={generated.rawKey} className="flex-1 bg-black/40 border border-white/10 rounded-lg px-3 py-2 text-xs font-mono text-neutral-100" />
              <button onClick={() => setGenerated({ ...generated, visible: !generated.visible })} className="p-2 rounded-lg border border-white/10 text-neutral-300">{generated.visible ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}</button>
              <button onClick={copy} className="p-2 rounded-lg border border-white/10 text-neutral-300">{copied ? <CheckCheck className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}</button>
            </div>
          </CardContent>
        </Card>
      )}

      <Card className="glass-card">
        <div className="p-4 border-b border-white/5 bg-black/20 flex items-center gap-2">
          <KeyRound className="w-4 h-4 text-blue-400" />
          <CardTitle className="text-base text-neutral-100">Create AuthClaw Gateway Key</CardTitle>
        </div>
        <CardContent className="p-4 flex flex-col md:flex-row gap-3">
          <input value={name} onChange={(event) => setName(event.target.value)} className="flex-1 bg-black/30 border border-white/10 rounded-lg px-3 py-2 text-sm text-neutral-100" placeholder="Key name" />
          <button onClick={create} disabled={createApiKey.isPending} className="rounded-lg bg-blue-600 hover:bg-blue-500 disabled:bg-blue-900 text-white px-4 py-2 text-sm font-medium">Generate Key</button>
        </CardContent>
      </Card>

      <Card className="glass-card overflow-hidden">
        <div className="p-4 border-b border-white/5 bg-black/20">
          <CardTitle className="text-base text-neutral-100">Key Metadata</CardTitle>
        </div>
        {isLoading ? (
          <div className="p-4"><TableSkeleton columns={6} rows={4} /></div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-neutral-900/80 border-b border-white/5">
              <tr>
                {['Name', 'Prefix', 'Scope', 'Last used', 'Status', 'Actions'].map((header) => <th key={header} className="text-left p-4 text-xs uppercase tracking-wider text-neutral-400">{header}</th>)}
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {keys.map((key) => (
                <tr key={key.id}>
                  <td className="p-4 text-neutral-100">{key.name}</td>
                  <td className="p-4 font-mono text-xs text-neutral-300">{key.key_prefix}********</td>
                  <td className="p-4 text-neutral-300">{key.scope || 'gateway_only'}</td>
                  <td className="p-4 text-neutral-400">{key.last_used_at ? new Date(key.last_used_at).toLocaleString() : 'Never'}</td>
                  <td className="p-4"><Badge variant="outline" className={key.is_active ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 'bg-neutral-500/10 text-neutral-400 border-neutral-700'}>{key.is_active ? 'Active' : 'Revoked'}</Badge></td>
                  <td className="p-4">
                    <button disabled={!key.is_active} onClick={() => revokeApiKey.mutate(key.id)} className="p-2 rounded-lg border border-red-500/20 text-red-300 disabled:text-neutral-600 disabled:border-neutral-800" title="Revoke key">
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
