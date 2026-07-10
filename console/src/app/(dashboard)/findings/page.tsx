"use client";

import { useMemo, useState } from 'react';
import { AlertTriangle, CheckCircle2, Eye, Filter, RefreshCw, ShieldAlert, ShieldOff } from 'lucide-react';
import { toast } from 'sonner';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardTitle } from '@/components/ui/card';
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import { EmptyState } from '@/components/shared/states';
import { TableSkeleton } from '@/components/shared/loaders';
import { useAuth } from '@/hooks/use-auth';
import {
  FindingStatus,
  SecurityFinding,
  useFindings,
  useIntegrations,
  useUpdateFindingStatus,
} from '@/hooks/use-data';

const PAGE_SIZE = 25;

type RoleAwareUser = {
  role?: string;
  role_name?: string;
  roles?: string[];
};

type ApiError = {
  response?: { data?: { detail?: string } };
  message?: string;
};

function userCanWrite(user: unknown) {
  const roleUser = (user || {}) as RoleAwareUser;
  const roles = [
    roleUser.role,
    roleUser.role_name,
    ...(Array.isArray(roleUser.roles) ? roleUser.roles : []),
  ].filter((role): role is string => typeof role === 'string' && role.length > 0).map((role) => role.toLowerCase());
  if (roles.length === 0) return true;
  return roles.some((role: string) => ['owner', 'admin', 'security_admin'].includes(role));
}

function severityTone(severity: string) {
  switch (severity) {
    case 'critical':
      return 'bg-red-500/10 text-red-400 border-red-500/20';
    case 'high':
      return 'bg-orange-500/10 text-orange-400 border-orange-500/20';
    case 'medium':
      return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
    default:
      return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
  }
}

function statusTone(status: string) {
  switch (status) {
    case 'active':
      return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
    case 'suppressed':
      return 'bg-neutral-800 text-neutral-400 border-neutral-700';
    case 'resolved':
      return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
    case 'remediating':
      return 'bg-violet-500/10 text-violet-400 border-violet-500/20';
    default:
      return 'bg-white/5 text-neutral-400 border-white/10';
  }
}

function errorMessage(error: unknown) {
  const apiError = error as ApiError;
  return apiError?.response?.data?.detail || apiError?.message || 'Request failed';
}

function DetailDrawer({
  finding,
  onClose,
  canWrite,
  onStatus,
  isUpdating,
}: {
  finding: SecurityFinding | null;
  onClose: () => void;
  canWrite: boolean;
  onStatus: (finding: SecurityFinding, status: FindingStatus) => void;
  isUpdating: boolean;
}) {
  return (
    <Sheet open={!!finding} onOpenChange={(open) => !open && onClose()}>
      <SheetContent className="w-full sm:max-w-2xl bg-[#0a0a0a] border-white/10 text-neutral-100 overflow-y-auto">
        {finding && (
          <>
            <SheetHeader className="border-b border-white/5">
              <SheetTitle className="text-lg">{finding.title}</SheetTitle>
              <SheetDescription className="font-mono text-xs">{finding.id}</SheetDescription>
            </SheetHeader>
            <div className="p-4 space-y-6">
              <div className="flex flex-wrap gap-2">
                <Badge variant="outline" className={severityTone(finding.severity)}>{finding.severity}</Badge>
                <Badge variant="outline" className={statusTone(finding.status)}>{finding.status}</Badge>
                <Badge variant="outline" className="border-white/10 text-neutral-300">{finding.provider_type}</Badge>
                {finding.service && <Badge variant="outline" className="border-white/10 text-neutral-300">{finding.service}</Badge>}
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                <Info label="Resource" value={finding.resource_id} mono />
                <Info label="Integration" value={finding.integration_id} mono />
                <Info label="Reference" value={finding.dedup_hash} mono />
                <Info label="Updated" value={new Date(finding.updated_at).toLocaleString()} />
              </div>

              <section>
                <h3 className="text-xs uppercase tracking-wider text-neutral-500 mb-2">Description</h3>
                <p className="text-sm text-neutral-300 leading-6">{finding.description || 'No normalized description available.'}</p>
              </section>

              {finding.remediation_instructions && (
                <section>
                  <h3 className="text-xs uppercase tracking-wider text-neutral-500 mb-2">Remediation</h3>
                  <p className="text-sm text-neutral-300 leading-6">{finding.remediation_instructions}</p>
                </section>
              )}

              <section>
                <h3 className="text-xs uppercase tracking-wider text-neutral-500 mb-2">Compliance tags</h3>
                {finding.compliance_tags?.length ? (
                  <div className="flex flex-wrap gap-2">{finding.compliance_tags.map((tag) => <Badge key={tag} variant="outline">{tag}</Badge>)}</div>
                ) : (
                  <p className="text-sm text-neutral-500">No tags attached.</p>
                )}
              </section>

              <div className="rounded-md border border-white/10 bg-white/[0.02] p-3 text-xs text-neutral-500">
                Raw provider payloads and credential material are not available in this console.
              </div>

              <div className="flex flex-wrap gap-2 pt-2">
                {finding.status === 'active' && (
                  <>
                    <Button variant="outline" disabled={!canWrite || isUpdating} onClick={() => {
                      if (window.confirm('Suppress this finding?')) onStatus(finding, 'suppressed');
                    }}><ShieldOff className="w-4 h-4 mr-1" /> Suppress</Button>
                    <Button variant="outline" disabled={!canWrite || isUpdating} onClick={() => {
                      if (window.confirm('Mark this finding resolved manually?')) onStatus(finding, 'resolved');
                    }}><CheckCircle2 className="w-4 h-4 mr-1" /> Resolve</Button>
                  </>
                )}
                {finding.status === 'suppressed' && (
                  <Button variant="outline" disabled={!canWrite || isUpdating} onClick={() => onStatus(finding, 'active')}><ShieldAlert className="w-4 h-4 mr-1" /> Reactivate</Button>
                )}
              </div>
            </div>
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}

function Info({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="rounded-md border border-white/10 bg-white/[0.02] p-3 min-w-0">
      <div className="text-[10px] uppercase tracking-wider text-neutral-500 mb-1">{label}</div>
      <div className={`text-neutral-300 break-words ${mono ? 'font-mono text-xs' : 'text-sm'}`}>{value}</div>
    </div>
  );
}

export default function FindingsPage() {
  const { user } = useAuth();
  const canWrite = userCanWrite(user);
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<SecurityFinding | null>(null);
  const [filters, setFilters] = useState({
    provider_type: '',
    integration_id: '',
    severity: '',
    status: 'active',
    service: '',
  });

  const query = useFindings({ ...filters, skip: page * PAGE_SIZE, limit: PAGE_SIZE });
  const integrationsQuery = useIntegrations({ skip: 0, limit: 100 });
  const updateStatus = useUpdateFindingStatus();
  const findings = query.data?.items || [];
  const total = query.data?.total || 0;
  const integrations = useMemo(() => integrationsQuery.data?.items || [], [integrationsQuery.data?.items]);
  const integrationMap = useMemo(() => Object.fromEntries(integrations.map((item) => [item.id, item])), [integrations]);

  const setFilter = (key: keyof typeof filters, value: string) => {
    setPage(0);
    setFilters((current) => ({ ...current, [key]: value }));
  };

  const changeStatus = async (finding: SecurityFinding, status: FindingStatus) => {
    try {
      const updated = await updateStatus.mutateAsync({ id: finding.id, status });
      toast.success('Finding status updated');
      setSelected(updated);
    } catch (err: unknown) {
      toast.error(errorMessage(err));
    }
  };

  return (
    <div className="space-y-6 max-w-[1600px] mx-auto pb-10">
      <div className="flex flex-col md:flex-row items-start md:items-end justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-neutral-100">Security Findings</h2>
          <p className="text-sm text-neutral-400 mt-1">Review normalized findings from connector scans and manage allowed status changes.</p>
        </div>
        <Button variant="outline" onClick={() => query.refetch()}><RefreshCw className="w-4 h-4 mr-2" /> Refresh</Button>
      </div>

      {!canWrite && <div className="rounded-md border border-amber-500/20 bg-amber-500/10 px-4 py-3 text-sm text-amber-300">Your role can view findings, but status actions are disabled.</div>}

      <Card className="glass-card">
        <CardContent className="p-4">
          <div className="flex items-center gap-2 mb-4">
            <Filter className="w-4 h-4 text-neutral-500" />
            <CardTitle className="text-neutral-100 text-base">Filters</CardTitle>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
            <FilterSelect label="Provider" value={filters.provider_type} onChange={(value) => setFilter('provider_type', value)} options={[['', 'All providers'], ['aws', 'AWS'], ['github', 'GitHub'], ['gcp', 'GCP']]} />
            <FilterSelect label="Integration" value={filters.integration_id} onChange={(value) => setFilter('integration_id', value)} options={[['', 'All integrations'], ...integrations.map((item) => [item.id, item.display_name || item.target_identifier] as [string, string])]} />
            <FilterSelect label="Severity" value={filters.severity} onChange={(value) => setFilter('severity', value)} options={[['', 'All severities'], ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low']]} />
            <FilterSelect label="Status" value={filters.status} onChange={(value) => setFilter('status', value)} options={[['', 'All statuses'], ['active', 'Active'], ['suppressed', 'Suppressed'], ['resolved', 'Resolved'], ['new', 'New'], ['remediating', 'Remediating']]} />
            <div className="space-y-1">
              <label className="text-[10px] uppercase tracking-wider text-neutral-500">Service</label>
              <input aria-label="Service" value={filters.service} onChange={(event) => setFilter('service', event.target.value)} placeholder="s3, iam, ghas" className="w-full h-9 rounded-md bg-black/40 border border-white/10 text-neutral-100 px-3 text-sm" />
            </div>
          </div>
        </CardContent>
      </Card>

      <Card className="glass-card overflow-hidden">
        <div className="p-4 border-b border-white/5 bg-black/20 flex items-center justify-between">
          <CardTitle className="text-neutral-100 text-base flex items-center gap-2"><AlertTriangle className="w-4 h-4 text-neutral-500" /> Findings</CardTitle>
          <span className="text-xs text-neutral-500">{total} total</span>
        </div>
        {query.isLoading ? (
          <div className="p-4"><TableSkeleton columns={9} rows={8} /></div>
        ) : findings.length === 0 ? (
          <EmptyState title={total === 0 ? 'No findings yet' : 'No findings match filters'} description="ConnectorWorker writes normalized findings after successful scans." icon={AlertTriangle} />
        ) : (
          <div className="overflow-auto">
            <table className="w-full text-sm">
              <thead className="bg-neutral-900/90 border-b border-white/5">
                <tr>
                  {['Severity', 'Title', 'Provider', 'Service', 'Resource', 'Status', 'Updated', 'Integration', 'Actions'].map((header) => (
                    <th key={header} className="text-left p-4 text-xs font-medium text-neutral-400 uppercase tracking-wider">{header}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {findings.map((finding) => (
                  <tr key={finding.id} className="hover:bg-white/[0.02]">
                    <td className="p-4"><Badge variant="outline" className={severityTone(finding.severity)}>{finding.severity}</Badge></td>
                    <td className="p-4 text-neutral-100 min-w-[260px]">{finding.title}</td>
                    <td className="p-4 uppercase text-neutral-300">{finding.provider_type}</td>
                    <td className="p-4 text-neutral-300">{finding.service || 'unknown'}</td>
                    <td className="p-4 text-neutral-400 font-mono text-xs max-w-[280px] truncate">{finding.resource_id}</td>
                    <td className="p-4"><Badge variant="outline" className={statusTone(finding.status)}>{finding.status}</Badge></td>
                    <td className="p-4 text-neutral-400 text-xs">{new Date(finding.updated_at).toLocaleString()}</td>
                    <td className="p-4 text-neutral-400 text-xs">{integrationMap[finding.integration_id]?.display_name || integrationMap[finding.integration_id]?.target_identifier || finding.integration_id.slice(0, 8)}</td>
                    <td className="p-4">
                      <div className="flex gap-2">
                        <Button size="sm" variant="outline" onClick={() => setSelected(finding)}><Eye className="w-3.5 h-3.5 mr-1" /> Detail</Button>
                        {finding.status === 'active' && (
                          <Button size="sm" variant="outline" disabled={!canWrite || updateStatus.isPending} onClick={() => {
                            if (window.confirm('Suppress this finding?')) changeStatus(finding, 'suppressed');
                          }}>Suppress</Button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="p-4 border-t border-white/5 flex items-center justify-between">
          <Button variant="outline" disabled={page === 0} onClick={() => setPage((current) => Math.max(0, current - 1))}>Previous</Button>
          <span className="text-xs text-neutral-500">Page {page + 1} of {Math.max(1, Math.ceil(total / PAGE_SIZE))}</span>
          <Button variant="outline" disabled={(page + 1) * PAGE_SIZE >= total} onClick={() => setPage((current) => current + 1)}>Next</Button>
        </div>
      </Card>

      <DetailDrawer finding={selected} onClose={() => setSelected(null)} canWrite={canWrite} onStatus={changeStatus} isUpdating={updateStatus.isPending} />
    </div>
  );
}

function FilterSelect({ label, value, onChange, options }: { label: string; value: string; onChange: (value: string) => void; options: [string, string][] }) {
  return (
    <div className="space-y-1">
      <label className="text-[10px] uppercase tracking-wider text-neutral-500">{label}</label>
      <select aria-label={label} value={value} onChange={(event) => onChange(event.target.value)} className="w-full h-9 rounded-md bg-black/40 border border-white/10 text-neutral-100 px-3 text-sm">
        {options.map(([optionValue, optionLabel]) => <option key={optionValue || optionLabel} value={optionValue}>{optionLabel}</option>)}
      </select>
    </div>
  );
}
