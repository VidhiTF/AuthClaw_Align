"use client";

import { useState } from 'react';
import { Activity, Clock } from 'lucide-react';
import { useGatewayRequests } from '@/hooks/use-data';
import { Card, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { TableSkeleton } from '@/components/shared/loaders';
import { EmptyState } from '@/components/shared/states';

type GatewayRequest = {
  id: string;
  created_at: string;
  status: string;
  model?: string | null;
  provider_id?: string | null;
  latency_ms?: number | null;
  provider_status_code?: number | null;
  error_message?: string | null;
};

function safeText(value: unknown) {
  const raw = typeof value === 'string' ? value : JSON.stringify(value ?? '', null, 2);
  return raw
    .replace(/raw_provider_payload/gi, '[redacted-source]')
    .replace(/vault[:/][^\s,"'}]+/gi, '[redacted-vault-ref]')
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, '[redacted-email]')
    .replace(/(?<!\d)(?:\+?\d[\d\s().-]{7,}\d)(?!\d)/g, '[redacted-phone]')
    .replace(/(token|secret|password|credential|api[_-]?key)\s*[:=]\s*[^,\s}]+/gi, '$1=[redacted]')
    .replace(/\b(?:sk-[a-z0-9*_=-]{8,}|gsk_[a-z0-9*_=-]{8,})\b/gi, '[redacted-provider-key]');
}

function StatusBadge({ status }: { status: string }) {
  const style =
    status === 'completed'
      ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
      : status === 'blocked'
      ? 'bg-red-500/10 text-red-400 border-red-500/20'
      : 'bg-amber-500/10 text-amber-400 border-amber-500/20';
  return <Badge variant="outline" className={style}>{status}</Badge>;
}

export default function GatewayTrafficPage() {
  const [status, setStatus] = useState('');
  const { data, isLoading } = useGatewayRequests(0, 100, status || undefined);
  const rows = (data?.items || []) as GatewayRequest[];

  return (
    <div className="space-y-6 max-w-[1500px] mx-auto pb-10">
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-neutral-100">Gateway Traffic</h2>
          <p className="text-sm text-neutral-400 mt-1">Metadata-only request inspector. Raw payloads and credentials are not shown.</p>
        </div>
        <select value={status} onChange={(event) => setStatus(event.target.value)} className="bg-black/30 border border-white/10 rounded-lg px-3 py-2 text-sm text-neutral-100">
          <option value="">All statuses</option>
          <option value="completed">Allowed</option>
          <option value="blocked">Blocked</option>
          <option value="error">Error</option>
        </select>
      </div>

      <Card className="glass-card overflow-hidden">
        <div className="p-4 border-b border-white/5 bg-black/20 flex items-center gap-2">
          <Activity className="w-4 h-4 text-blue-400" />
          <CardTitle className="text-base text-neutral-100">Traffic Inspector</CardTitle>
        </div>
        {isLoading ? (
          <div className="p-4"><TableSkeleton columns={6} rows={8} /></div>
        ) : rows.length === 0 ? (
          <EmptyState title="No traffic found" description="Send a gateway request to populate this inspector." icon={Activity} />
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-neutral-900/80 border-b border-white/5">
              <tr>
                {['Time', 'Request ID', 'Provider', 'Model', 'Decision', 'Latency', 'Context'].map((header) => <th key={header} className="text-left p-4 text-xs uppercase tracking-wider text-neutral-400">{header}</th>)}
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {rows.map((row) => (
                <tr key={row.id}>
                  <td className="p-4 text-neutral-400 whitespace-nowrap"><Clock className="inline w-3.5 h-3.5 mr-2" />{new Date(row.created_at).toLocaleString()}</td>
                  <td className="p-4 font-mono text-xs text-neutral-500">{row.id}</td>
                  <td className="p-4 font-mono text-xs text-neutral-400">{row.provider_id ? row.provider_id.slice(0, 8) : 'unresolved'}</td>
                  <td className="p-4 font-mono text-xs text-neutral-300">{row.model || 'unknown'}</td>
                  <td className="p-4"><StatusBadge status={row.status} /></td>
                  <td className="p-4 font-mono text-xs text-neutral-400">{row.latency_ms ? `${row.latency_ms}ms` : '-'}</td>
                  <td className="p-4 text-xs text-neutral-400 max-w-md truncate">{row.error_message ? safeText(row.error_message) : row.status === 'completed' ? 'Forwarded to provider' : 'Policy decision recorded'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
