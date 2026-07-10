"use client";

import Link from 'next/link';
import { useMemo, useState } from 'react';
import {
  Activity,
  Archive,
  Bell,
  CheckCircle2,
  ClipboardList,
  Database,
  FileJson,
  FileText,
  HeartPulse,
  LockKeyhole,
  PackageCheck,
  Plus,
  Share2,
  ShieldCheck,
  Wrench,
} from 'lucide-react';
import { toast } from 'sonner';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardTitle } from '@/components/ui/card';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import { EmptyState } from '@/components/shared/states';
import { TableSkeleton } from '@/components/shared/loaders';
import { useAuth } from '@/hooks/use-auth';
import {
  ActivityTimelineItem,
  AuditExportVerificationStateInfo,
  ExportManifest,
  ReportAccessLog,
  ReportArtifactDownload,
  ReportArtifactMetadata,
  ReportRun,
  ReportTemplate,
  TrustNotification,
  TrustPosture,
  useActivityTimeline,
  useAuditExportVerificationStates,
  useCreateEvidencePackage,
  useCreateReportRun,
  useCreateReportTemplate,
  useCreateShareLink,
  useDeleteReportTemplate,
  useDownloadReportArtifact,
  useEvidencePackages,
  useMarkAllTrustNotificationsRead,
  useMarkTrustNotificationRead,
  useNotificationUnreadCount,
  useReportAccessLogs,
  useReportArtifactManifest,
  useReportArtifacts,
  useReportRuns,
  useReportTemplates,
  useRevokeShareLink,
  useShareLinks,
  useTrustNotifications,
  useTrustOverview,
  useTrustPosture,
  useUpdateReportTemplate,
} from '@/hooks/use-data';

type TrustPostureView = 'security' | 'compliance' | 'remediation' | 'integrations';
type TrustView = 'overview' | TrustPostureView | 'activity';
type ReportView = 'overview' | 'templates' | 'runs' | 'artifacts' | 'evidence-packages' | 'access-logs';
type RoleAwareUser = { role?: string; role_name?: string; roles?: string[] };
type ApiError = { response?: { data?: { detail?: string } }; message?: string };

const PAGE_SIZE = 50;

const trustNav: Array<{ view: TrustView; label: string; href: string; icon: typeof ShieldCheck }> = [
  { view: 'overview', label: 'Overview', href: '/trust', icon: ShieldCheck },
  { view: 'security', label: 'Security', href: '/trust/security', icon: LockKeyhole },
  { view: 'compliance', label: 'Compliance', href: '/trust/compliance', icon: ClipboardList },
  { view: 'remediation', label: 'Remediation', href: '/trust/remediation', icon: Wrench },
  { view: 'integrations', label: 'Integrations', href: '/trust/integrations', icon: HeartPulse },
  { view: 'activity', label: 'Activity', href: '/trust/activity', icon: Activity },
];

const reportNav: Array<{ view: ReportView; label: string; href: string; icon: typeof FileText }> = [
  { view: 'overview', label: 'Overview', href: '/reports', icon: FileText },
  { view: 'templates', label: 'Templates', href: '/reports/templates', icon: ClipboardList },
  { view: 'runs', label: 'Runs', href: '/reports/runs', icon: Activity },
  { view: 'artifacts', label: 'Artifacts', href: '/reports/artifacts', icon: Archive },
  { view: 'evidence-packages', label: 'Evidence packages', href: '/reports/evidence-packages', icon: PackageCheck },
  { view: 'access-logs', label: 'Access logs', href: '/reports/access-logs', icon: Database },
];

function rolesFor(user: unknown) {
  const roleUser = (user || {}) as RoleAwareUser;
  const roles = [
    roleUser.role,
    roleUser.role_name,
    ...(Array.isArray(roleUser.roles) ? roleUser.roles : []),
  ].filter((role): role is string => typeof role === 'string' && role.length > 0).map((role) => role.toLowerCase());
  return roles.length ? roles : ['owner'];
}

function hasAnyRole(user: unknown, allowed: string[]) {
  return rolesFor(user).some((role) => allowed.includes(role));
}

function permissionsFor(user: unknown) {
  return {
    canViewTrust: true,
    canViewReports: hasAnyRole(user, ['owner', 'admin', 'auditor', 'analyst']),
    canGenerate: hasAnyRole(user, ['owner', 'admin', 'auditor']),
    canDownload: hasAnyRole(user, ['owner', 'admin', 'auditor']),
    canManageTemplates: hasAnyRole(user, ['owner', 'admin']),
    canViewAccessLogs: hasAnyRole(user, ['owner', 'admin', 'auditor']),
    canShare: hasAnyRole(user, ['owner', 'admin', 'auditor']),
  };
}

function errorMessage(error: unknown) {
  const apiError = error as ApiError;
  return apiError?.response?.data?.detail || apiError?.message || 'Request failed';
}

export function safeExportText(value: unknown) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/raw_provider_payload/gi, '[redacted-source]')
    .replace(/raw[_\s-]?artifact/gi, '[redacted-artifact]')
    .replace(/vault[:/][^\s,"'}]+/gi, '[redacted-vault-ref]')
    .replace(/authclaw\/tenants\/[^\s,"'}]+/gi, '[redacted-vault-ref]')
    .replace(/authorization\s*[:=]\s*bearer\s+[^\s,"'}]+/gi, 'authorization=[redacted]')
    .replace(/(token|secret|password|credential|api[_-]?key)\s*[:=]\s*[^,\s}]+/gi, '$1=[redacted]')
    .replace(/-----BEGIN [^-]+PRIVATE KEY-----[\s\S]*?-----END [^-]+PRIVATE KEY-----/g, '[redacted-private-key]')
    .replace(/gh[pousr]_[a-z0-9_]+/gi, '[redacted-token]')
    .replace(/AKIA[0-9A-Z]{12,}/g, '[redacted-key]');
}

function labelText(value?: string | null) {
  return safeExportText(value || 'unknown').replaceAll('_', ' ');
}

function dateText(value?: string | null) {
  if (!value) return 'Not recorded';
  return new Date(value).toLocaleString();
}

function numberText(value: unknown) {
  return typeof value === 'number' ? value.toLocaleString() : safeExportText(value || 0);
}

function statusTone(value?: string | null) {
  switch (value) {
    case 'completed':
    case 'active':
    case 'healthy':
    case 'evidence-supported posture':
    case 'Verified':
      return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
    case 'queued':
    case 'running':
    case 'needs review':
    case 'gap detected':
      return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
    case 'at risk':
    case 'expired':
    case 'Unknown':
    case 'Unsupported Version':
      return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
    case 'failed':
    case 'critical':
    case 'high':
    case 'error':
    case 'Tampered':
    case 'Verification Failed':
    case 'Error':
      return 'bg-red-500/10 text-red-400 border-red-500/20';
    default:
      return 'bg-white/5 text-neutral-300 border-white/10';
  }
}

function LabelBadge({ value, tone = statusTone }: { value?: string | null; tone?: (value?: string | null) => string }) {
  return <Badge variant="outline" className={tone(value)}>{labelText(value)}</Badge>;
}

function FilterSelect({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: Array<[string, string]>;
}) {
  return (
    <div className="space-y-1">
      <label className="text-[10px] uppercase tracking-wider text-neutral-500">{label}</label>
      <select
        aria-label={label}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="w-full h-9 rounded-md bg-black/40 border border-white/10 text-neutral-100 px-3 text-sm"
      >
        {options.map(([optionValue, optionLabel]) => (
          <option key={optionValue || optionLabel} value={optionValue}>{optionLabel}</option>
        ))}
      </select>
    </div>
  );
}

function Info({ label, value, mono = false }: { label: string; value?: unknown; mono?: boolean }) {
  return (
    <div className="rounded-md border border-white/10 bg-white/[0.02] p-3 min-w-0">
      <div className="text-[10px] uppercase tracking-wider text-neutral-500 mb-1">{label}</div>
      <div className={`text-neutral-300 break-words ${mono ? 'font-mono text-xs' : 'text-sm'}`}>{safeExportText(value || '-')}</div>
    </div>
  );
}

function Metric({ label, value, hint }: { label: string; value: string | number; hint: string }) {
  return (
    <Card className="glass-card">
      <CardContent className="p-4">
        <div className="text-xs uppercase tracking-wider text-neutral-500">{label}</div>
        <div className="mt-3 text-3xl font-semibold text-neutral-100">{value}</div>
        <div className="mt-1 text-xs text-neutral-400">{hint}</div>
      </CardContent>
    </Card>
  );
}

function DataTable({
  headers,
  children,
  loading,
  emptyTitle,
  emptyDescription,
}: {
  headers: string[];
  children: React.ReactNode;
  loading?: boolean;
  emptyTitle: string;
  emptyDescription: string;
}) {
  if (loading) return <div className="p-4"><TableSkeleton columns={headers.length} rows={6} /></div>;
  const rows = Array.isArray(children) ? children.filter(Boolean) : children;
  if (!rows || (Array.isArray(rows) && rows.length === 0)) {
    return <EmptyState title={emptyTitle} description={emptyDescription} icon={FileText} />;
  }
  return (
    <div className="overflow-auto">
      <table className="w-full text-sm">
        <thead className="bg-neutral-900/90 border-b border-white/5">
          <tr>
            {headers.map((header) => (
              <th key={header} className="text-left p-4 text-xs font-medium text-neutral-400 uppercase tracking-wider">{header}</th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-white/5">{children}</tbody>
      </table>
    </div>
  );
}

function TrustShell({ view, children }: { view: TrustView; children: React.ReactNode }) {
  return (
    <div className="space-y-6 max-w-[1600px] mx-auto pb-10">
      <div className="flex flex-col xl:flex-row items-start xl:items-end justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-neutral-100">Trust Center</h2>
          <p className="text-sm text-neutral-400 mt-1">Evidence-supported posture across findings, mapped controls, remediation, and integration health.</p>
        </div>
        <div className="flex flex-wrap gap-2">
          {trustNav.map((item) => {
            const Icon = item.icon;
            const active = view === item.view;
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`inline-flex h-9 items-center gap-2 rounded-md border px-3 text-sm transition-colors ${
                  active ? 'border-blue-500/30 bg-blue-500/10 text-blue-300' : 'border-white/10 bg-black/20 text-neutral-300 hover:bg-white/[0.04]'
                }`}
              >
                <Icon className="h-4 w-4" />
                {item.label}
              </Link>
            );
          })}
        </div>
      </div>
      <div className="rounded-md border border-blue-500/20 bg-blue-500/10 px-4 py-3 text-sm text-blue-200">
        Not legal advice. This view summarizes posture, mapped controls, and evidence freshness for review.
      </div>
      {children}
    </div>
  );
}

function ReportShell({ view, children }: { view: ReportView; children: React.ReactNode }) {
  return (
    <div className="space-y-6 max-w-[1600px] mx-auto pb-10">
      <div className="flex flex-col xl:flex-row items-start xl:items-end justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-neutral-100">Report Center</h2>
          <p className="text-sm text-neutral-400 mt-1">Generate JSON report and evidence package metadata from sanitized tenant-scoped records.</p>
        </div>
        <div className="flex flex-wrap gap-2">
          {reportNav.map((item) => {
            const Icon = item.icon;
            const active = view === item.view;
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`inline-flex h-9 items-center gap-2 rounded-md border px-3 text-sm transition-colors ${
                  active ? 'border-blue-500/30 bg-blue-500/10 text-blue-300' : 'border-white/10 bg-black/20 text-neutral-300 hover:bg-white/[0.04]'
                }`}
              >
                <Icon className="h-4 w-4" />
                {item.label}
              </Link>
            );
          })}
        </div>
      </div>
      <div className="rounded-md border border-amber-500/20 bg-amber-500/10 px-4 py-3 text-sm text-amber-200">
        Metadata only. Raw report bodies, provider payloads, credentials, external shares, and export file actions are intentionally absent.
      </div>
      {children}
    </div>
  );
}

function NoReportAccess() {
  return (
    <ReportShell view="overview">
      <Card className="glass-card">
        <CardContent className="p-5">
          <CardTitle className="text-neutral-100 text-base">Report Center access requires analyst, auditor, admin, or owner role.</CardTitle>
          <p className="text-sm text-neutral-400 mt-2">Viewer roles can still review Trust Center summaries.</p>
        </CardContent>
      </Card>
    </ReportShell>
  );
}

function keyValueRows(source: Record<string, unknown> | undefined) {
  return Object.entries(source || {}).filter(([, value]) => value !== null && value !== undefined);
}

function PostureCard({ title, posture, icon: Icon }: { title: string; posture?: TrustPosture; icon: typeof ShieldCheck }) {
  const totalCounts = keyValueRows(posture?.counts);
  return (
    <Card className="glass-card">
      <CardContent className="p-5 space-y-4">
        <div className="flex items-start justify-between gap-3">
          <div>
            <CardTitle className="text-neutral-100 text-base flex items-center gap-2"><Icon className="h-4 w-4 text-blue-400" /> {title}</CardTitle>
            <div className="mt-2 flex flex-wrap gap-2">
              <LabelBadge value={posture?.posture || 'needs review'} />
              <Badge variant="outline" className="border-white/10 text-neutral-300">last updated {dateText(posture?.generated_at)}</Badge>
            </div>
          </div>
        </div>
        <div className="grid grid-cols-2 gap-3">
          {totalCounts.slice(0, 4).map(([key, value]) => <Info key={key} label={key.replaceAll('_', ' ')} value={numberText(value)} />)}
          {totalCounts.length === 0 && <Info label="records" value="0" />}
        </div>
      </CardContent>
    </Card>
  );
}

function AuditExportVerificationCard({ states, loading }: { states: AuditExportVerificationStateInfo[]; loading?: boolean }) {
  const visibleStates = states.length ? states : [
    { state: 'Unknown', severity: 'medium', meaning: 'Verification state metadata is not available yet.' },
  ];
  return (
    <Card className="glass-card xl:col-span-2">
      <div className="p-4 border-b border-white/5 bg-black/20 flex items-center justify-between gap-3">
        <CardTitle className="text-neutral-100 text-base flex items-center gap-2">
          <PackageCheck className="h-4 w-4 text-emerald-400" />
          Audit export verification
        </CardTitle>
        <Badge variant="outline" className="border-white/10 text-neutral-300">signed package states</Badge>
      </div>
      <DataTable headers={['State', 'Severity', 'Meaning']} loading={loading} emptyTitle="No verification states" emptyDescription="The Trust Center has not returned audit export verification states.">
        {visibleStates.map((item) => (
          <tr key={item.state} className="hover:bg-white/[0.02]">
            <td className="p-4"><LabelBadge value={item.state} /></td>
            <td className="p-4 text-neutral-300">{safeExportText(item.severity)}</td>
            <td className="p-4 text-neutral-300">{safeExportText(item.meaning)}</td>
          </tr>
        ))}
      </DataTable>
    </Card>
  );
}

function PostureDetail({ kind }: { kind: TrustPostureView }) {
  const postureKind = kind;
  const query = useTrustPosture(postureKind);
  const titleByKind = {
    security: 'Security posture',
    compliance: 'Compliance posture',
    remediation: 'Remediation posture',
    integrations: 'Integration health',
  } as const;
  const posture = query.data;
  return (
    <TrustShell view={kind}>
      <div className="grid gap-4 md:grid-cols-4">
        <Metric label="Posture" value={labelText(posture?.posture || 'needs review')} hint="Evidence-supported state" />
        <Metric label="Last updated" value={posture?.generated_at ? new Date(posture.generated_at).toLocaleDateString() : '-'} hint="API generated timestamp" />
        <Metric label="Statuses" value={Object.keys(posture?.status_counts || {}).length} hint="Status groups returned" />
        <Metric label="Freshness" value={Object.keys(posture?.freshness || {}).length} hint="Freshness fields returned" />
      </div>
      <div className="grid gap-6 xl:grid-cols-2">
        <CountTable title={`${titleByKind[postureKind]} counts`} counts={posture?.counts || {}} loading={query.isLoading} />
        <CountTable title="Status counts" counts={posture?.status_counts || {}} loading={query.isLoading} />
        <CountTable title="Severity counts" counts={posture?.severity_counts || {}} loading={query.isLoading} />
        <CountTable title="Evidence freshness" counts={posture?.freshness || {}} loading={query.isLoading} />
      </div>
    </TrustShell>
  );
}

function CountTable({ title, counts, loading }: { title: string; counts: Record<string, unknown>; loading?: boolean }) {
  return (
    <Card className="glass-card overflow-hidden">
      <div className="p-4 border-b border-white/5 bg-black/20">
        <CardTitle className="text-neutral-100 text-base">{title}</CardTitle>
      </div>
      <DataTable headers={['Field', 'Value']} loading={loading} emptyTitle="No counts returned" emptyDescription="The API returned no rows for this section.">
        {keyValueRows(counts).map(([key, value]) => (
          <tr key={key} className="hover:bg-white/[0.02]">
            <td className="p-4 text-neutral-300">{safeExportText(key).replaceAll('_', ' ')}</td>
            <td className="p-4 text-neutral-100 font-medium">{numberText(value)}</td>
          </tr>
        ))}
      </DataTable>
    </Card>
  );
}

function TrustOverviewView() {
  const overviewQuery = useTrustOverview();
  const verificationStatesQuery = useAuditExportVerificationStates();
  const overview = overviewQuery.data;
  return (
    <TrustShell view="overview">
      <div className="grid gap-4 md:grid-cols-4">
        <Metric label="Overall posture" value={overview ? 'needs review' : '-'} hint="Review all evidence sources" />
        <Metric label="Mapped controls" value={numberText(overview?.compliance_posture?.counts?.mapped_controls || 0)} hint="Controls linked to evidence" />
        <Metric label="Findings" value={numberText(overview?.security_posture?.counts?.findings || 0)} hint="Security findings in scope" />
        <Metric label="Last updated" value={overview?.generated_at ? new Date(overview.generated_at).toLocaleDateString() : '-'} hint="Trust API timestamp" />
      </div>
      <div className="grid gap-6 xl:grid-cols-2">
        <PostureCard title="Security posture" posture={overview?.security_posture} icon={LockKeyhole} />
        <PostureCard title="Compliance posture" posture={overview?.compliance_posture} icon={ClipboardList} />
        <PostureCard title="Remediation posture" posture={overview?.remediation_posture} icon={Wrench} />
        <PostureCard title="Integration health" posture={overview?.integration_health} icon={HeartPulse} />
        <AuditExportVerificationCard states={verificationStatesQuery.data?.states || []} loading={verificationStatesQuery.isLoading} />
      </div>
      {overviewQuery.isLoading && <TableSkeleton columns={4} rows={3} />}
    </TrustShell>
  );
}

function ActivityTimelineView() {
  const [filters, setFilters] = useState({ source: '', action: '', resource_type: '' });
  const timelineQuery = useActivityTimeline({ ...filters, skip: 0, limit: PAGE_SIZE });
  const items = timelineQuery.data?.items || [];
  return (
    <TrustShell view="activity">
      <div className="grid gap-4 md:grid-cols-4">
        <Metric label="Timeline items" value={timelineQuery.data?.total ?? 0} hint="Sanitized tenant events" />
        <Metric label="Reports" value={items.filter((item) => item.source === 'report').length} hint="Runs and metadata access" />
        <Metric label="Remediation" value={items.filter((item) => item.source === 'remediation').length} hint="Approvals and verification" />
        <Metric label="Last updated" value={items[0]?.occurred_at ? new Date(items[0].occurred_at).toLocaleDateString() : '-'} hint="Latest activity timestamp" />
      </div>
      <Card className="glass-card">
        <CardContent className="p-4">
          <div className="grid md:grid-cols-3 gap-3">
            <FilterSelect label="Source" value={filters.source} onChange={(value) => setFilters((current) => ({ ...current, source: value }))} options={[['', 'All sources'], ['report', 'Report'], ['remediation', 'Remediation'], ['evidence', 'Evidence'], ['integration', 'Integration']]} />
            <FilterSelect label="Resource type" value={filters.resource_type} onChange={(value) => setFilters((current) => ({ ...current, resource_type: value }))} options={[['', 'All resources'], ['report_run', 'Report run'], ['report_artifact', 'Report artifact'], ['remediation_approval', 'Approval'], ['remediation_plan', 'Plan'], ['evidence_item', 'Evidence'], ['cloud_integration', 'Integration']]} />
            <Input aria-label="Action" placeholder="action filter" value={filters.action} onChange={(event) => setFilters((current) => ({ ...current, action: event.target.value }))} className="bg-black/40 border-white/10 text-neutral-100" />
          </div>
        </CardContent>
      </Card>
      <ActivityTimelineTable items={items} loading={timelineQuery.isLoading} />
    </TrustShell>
  );
}

function ActivityTimelineTable({ items, loading }: { items: ActivityTimelineItem[]; loading?: boolean }) {
  return (
    <Card className="glass-card overflow-hidden">
      <div className="p-4 border-b border-white/5 bg-black/20 flex items-center gap-2">
        <Activity className="h-4 w-4 text-blue-400" />
        <CardTitle className="text-neutral-100 text-base">Activity timeline</CardTitle>
      </div>
      <DataTable headers={['Time', 'Source', 'Action', 'Resource', 'Summary', 'Actor', 'Metadata']} loading={loading} emptyTitle="No activity" emptyDescription="Sanitized trust, report, remediation, evidence, and integration activity appears here.">
        {items.map((item) => (
          <tr key={item.id} className="hover:bg-white/[0.02] align-top">
            <td className="p-4 text-neutral-400 text-xs whitespace-nowrap">{dateText(item.occurred_at)}</td>
            <td className="p-4"><LabelBadge value={item.source} /></td>
            <td className="p-4"><LabelBadge value={item.action} /></td>
            <td className="p-4">
              <div className="text-neutral-300">{labelText(item.resource_type)}</div>
              <div className="font-mono text-xs text-neutral-500 max-w-[180px] truncate">{safeExportText(item.resource_id || '-')}</div>
            </td>
            <td className="p-4 min-w-[260px]">
              <div className="text-neutral-100 font-medium">{safeExportText(item.title)}</div>
              <div className="text-neutral-400 text-xs mt-1">{safeExportText(item.summary)}</div>
            </td>
            <td className="p-4 font-mono text-xs text-neutral-400 max-w-[180px] truncate">{safeExportText(item.actor_user_id || '-')}</td>
            <td className="p-4">
              <pre className="max-w-[260px] max-h-24 overflow-auto rounded-md border border-white/10 bg-black/40 p-2 text-[11px] text-neutral-400 whitespace-pre-wrap break-words">{safeExportText(JSON.stringify(item.metadata || {}, null, 2))}</pre>
            </td>
          </tr>
        ))}
      </DataTable>
    </Card>
  );
}

function ReportOverviewView({ canGenerate, canDownload }: { canGenerate: boolean; canDownload: boolean }) {
  const templatesQuery = useReportTemplates({ skip: 0, limit: PAGE_SIZE });
  const runsQuery = useReportRuns({ skip: 0, limit: PAGE_SIZE });
  const artifactsQuery = useReportArtifacts({ skip: 0, limit: PAGE_SIZE });
  const packagesQuery = useEvidencePackages({ skip: 0, limit: PAGE_SIZE });
  const completedRuns = (runsQuery.data?.items || []).filter((run) => run.status === 'completed');
  return (
    <ReportShell view="overview">
      {!canGenerate && <RoleNotice text="Your role can view report history, but report and evidence package generation is disabled." />}
      <div className="grid gap-4 md:grid-cols-4">
        <Metric label="Templates" value={templatesQuery.data?.total ?? 0} hint="JSON report definitions" />
        <Metric label="Runs" value={runsQuery.data?.total ?? 0} hint="Queued through completed jobs" />
        <Metric label="Completed" value={completedRuns.length} hint="Successful report runs" />
        <Metric label="Artifacts" value={artifactsQuery.data?.total ?? 0} hint="Metadata records only" />
      </div>
      <div className="grid gap-6 xl:grid-cols-2">
        <RunsTable runs={(runsQuery.data?.items || []).slice(0, 8)} loading={runsQuery.isLoading} compact />
        <ArtifactsTable artifacts={(artifactsQuery.data?.items || []).slice(0, 8)} loading={artifactsQuery.isLoading} canDownload={canDownload} />
      </div>
      <Card className="glass-card overflow-hidden">
        <div className="p-4 border-b border-white/5 bg-black/20 flex items-center justify-between">
          <CardTitle className="text-neutral-100 text-base">Recent evidence packages</CardTitle>
          <Link className="text-xs text-blue-300 hover:text-blue-200" href="/reports/evidence-packages">Open builder</Link>
        </div>
        <RunsTable runs={packagesQuery.data?.items || []} loading={packagesQuery.isLoading} compact />
      </Card>
    </ReportShell>
  );
}

function RoleNotice({ text }: { text: string }) {
  return <div className="rounded-md border border-amber-500/20 bg-amber-500/10 px-4 py-3 text-sm text-amber-300">{text}</div>;
}

function TemplatesView({ canManageTemplates }: { canManageTemplates: boolean }) {
  const templatesQuery = useReportTemplates({ skip: 0, limit: PAGE_SIZE });
  const createTemplate = useCreateReportTemplate();
  const updateTemplate = useUpdateReportTemplate();
  const deleteTemplate = useDeleteReportTemplate();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editing, setEditing] = useState<ReportTemplate | null>(null);
  const [form, setForm] = useState({ name: '', type: 'trust_overview', sections: 'summary,posture,evidence', filterKey: '', filterValue: '' });

  const openCreate = () => {
    setEditing(null);
    setForm({ name: '', type: 'trust_overview', sections: 'summary,posture,evidence', filterKey: '', filterValue: '' });
    setDialogOpen(true);
  };

  const openEdit = (template: ReportTemplate) => {
    setEditing(template);
    setForm({
      name: template.name,
      type: template.type,
      sections: template.default_sections.map(String).join(','),
      filterKey: '',
      filterValue: '',
    });
    setDialogOpen(true);
  };

  const submit = async () => {
    const filters_schema = form.filterKey.trim() ? { [form.filterKey.trim()]: safeExportText(form.filterValue) } : {};
    const default_sections = form.sections.split(',').map((item) => item.trim()).filter(Boolean);
    try {
      if (editing) {
        await updateTemplate.mutateAsync({ id: editing.id, data: { name: form.name, type: form.type, filters_schema, default_sections } });
        toast.success('Template updated');
      } else {
        await createTemplate.mutateAsync({ name: form.name, type: form.type, format: 'json', filters_schema, default_sections });
        toast.success('Template created');
      }
      setDialogOpen(false);
    } catch (err: unknown) {
      toast.error(errorMessage(err));
    }
  };

  return (
    <ReportShell view="templates">
      {!canManageTemplates && <RoleNotice text="Template create, edit, and delete controls are disabled for this role." />}
      <Card className="glass-card overflow-hidden">
        <div className="p-4 border-b border-white/5 bg-black/20 flex items-center justify-between gap-3">
          <CardTitle className="text-neutral-100 text-base flex items-center gap-2"><ClipboardList className="h-4 w-4 text-blue-400" /> Report templates</CardTitle>
          <Button disabled={!canManageTemplates} onClick={openCreate}><Plus className="h-4 w-4 mr-2" />New template</Button>
        </div>
        <DataTable headers={['Name', 'Type', 'Format', 'Sections', 'Updated', 'Actions']} loading={templatesQuery.isLoading} emptyTitle="No templates" emptyDescription="Admin and owner roles can create JSON report templates.">
          {(templatesQuery.data?.items || []).map((template) => (
            <tr key={template.id} className="hover:bg-white/[0.02]">
              <td className="p-4 text-neutral-100 font-medium">{safeExportText(template.name)}</td>
              <td className="p-4"><LabelBadge value={template.type} /></td>
              <td className="p-4"><LabelBadge value={template.format} /></td>
              <td className="p-4 text-neutral-300">{template.default_sections.map(safeExportText).join(', ') || '-'}</td>
              <td className="p-4 text-neutral-400 text-xs">{dateText(template.updated_at)}</td>
              <td className="p-4">
                <div className="flex flex-wrap gap-2">
                  <Button size="sm" variant="outline" disabled={!canManageTemplates} onClick={() => openEdit(template)}>Edit</Button>
                  <Button size="sm" variant="outline" disabled={!canManageTemplates || template.is_system || deleteTemplate.isPending} onClick={() => deleteTemplate.mutate(template.id)}>Delete</Button>
                </div>
              </td>
            </tr>
          ))}
        </DataTable>
      </Card>
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="max-w-xl bg-[#0a0a0a] border-white/10 text-neutral-100">
          <DialogHeader>
            <DialogTitle>{editing ? 'Edit report template' : 'Create report template'}</DialogTitle>
            <DialogDescription>Templates define JSON report metadata and filters only.</DialogDescription>
          </DialogHeader>
          <div className="grid gap-3">
            <Input aria-label="Template name" value={form.name} onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))} placeholder="Quarterly posture package" />
            <FilterSelect label="Report type" value={form.type} onChange={(value) => setForm((current) => ({ ...current, type: value }))} options={[['trust_overview', 'Trust overview'], ['evidence_package', 'Evidence package'], ['control_evidence', 'Control evidence']]} />
            <Input aria-label="Default sections" value={form.sections} onChange={(event) => setForm((current) => ({ ...current, sections: event.target.value }))} placeholder="summary,posture,evidence" />
            <div className="grid md:grid-cols-2 gap-3">
              <Input aria-label="Filter key" value={form.filterKey} onChange={(event) => setForm((current) => ({ ...current, filterKey: event.target.value }))} placeholder="Optional filter key" />
              <Input aria-label="Filter value" value={form.filterValue} onChange={(event) => setForm((current) => ({ ...current, filterValue: event.target.value }))} placeholder="Optional filter value" />
            </div>
          </div>
          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setDialogOpen(false)}>Cancel</Button>
            <Button disabled={!form.name.trim() || createTemplate.isPending || updateTemplate.isPending} onClick={submit}>{editing ? 'Save template' : 'Create template'}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </ReportShell>
  );
}

function RunsView({ canGenerate }: { canGenerate: boolean }) {
  const [filters, setFilters] = useState({ status: '', report_type: '' });
  const [selected, setSelected] = useState<ReportRun | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const runsQuery = useReportRuns({ ...filters, skip: 0, limit: PAGE_SIZE });
  return (
    <ReportShell view="runs">
      {!canGenerate && <RoleNotice text="Report generation is disabled for this role. Existing history remains visible where permitted." />}
      <RunCreator open={dialogOpen} onOpenChange={setDialogOpen} onCreated={setSelected} canGenerate={canGenerate} />
      <Card className="glass-card">
        <CardContent className="p-4">
          <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
            <div className="grid md:grid-cols-2 gap-3 flex-1">
              <FilterSelect label="Status" value={filters.status} onChange={(value) => setFilters((current) => ({ ...current, status: value }))} options={[['', 'All statuses'], ['queued', 'Queued'], ['running', 'Running'], ['completed', 'Completed'], ['failed', 'Failed'], ['expired', 'Expired']]} />
              <FilterSelect label="Report type" value={filters.report_type} onChange={(value) => setFilters((current) => ({ ...current, report_type: value }))} options={[['', 'All types'], ['trust_overview', 'Trust overview'], ['evidence_package', 'Evidence package'], ['control_evidence', 'Control evidence']]} />
            </div>
            <Button disabled={!canGenerate} onClick={() => setDialogOpen(true)}><Plus className="h-4 w-4 mr-2" />Create run</Button>
          </div>
        </CardContent>
      </Card>
      <RunsTable runs={runsQuery.data?.items || []} loading={runsQuery.isLoading} onSelect={setSelected} />
      <RunDetailSheet run={selected} onClose={() => setSelected(null)} />
    </ReportShell>
  );
}

function RunCreator({
  open,
  onOpenChange,
  onCreated,
  canGenerate,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated: (run: ReportRun) => void;
  canGenerate: boolean;
}) {
  const templatesQuery = useReportTemplates({ skip: 0, limit: PAGE_SIZE });
  const createRun = useCreateReportRun();
  const [form, setForm] = useState({ template_id: '', report_type: 'trust_overview', scope: 'executive', retention_days: '90' });
  const submit = async () => {
    try {
      const run = await createRun.mutateAsync({
        template_id: form.template_id || null,
        report_type: form.report_type,
        filters: { scope: safeExportText(form.scope) },
        retention_days: Number(form.retention_days) || 90,
      });
      toast.success('Report run created');
      onCreated(run);
      onOpenChange(false);
    } catch (err: unknown) {
      toast.error(errorMessage(err));
    }
  };
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-xl bg-[#0a0a0a] border-white/10 text-neutral-100">
        <DialogHeader>
          <DialogTitle>Create report run</DialogTitle>
          <DialogDescription>Creates a sanitized JSON report artifact record when generation completes.</DialogDescription>
        </DialogHeader>
        <div className="grid gap-3">
          <FilterSelect label="Template" value={form.template_id} onChange={(value) => setForm((current) => ({ ...current, template_id: value }))} options={[['', 'No template'], ...(templatesQuery.data?.items || []).map((item) => [item.id, item.name] as [string, string])]} />
          <FilterSelect label="Report type" value={form.report_type} onChange={(value) => setForm((current) => ({ ...current, report_type: value }))} options={[['trust_overview', 'Trust overview'], ['control_evidence', 'Control evidence']]} />
          <Input aria-label="Scope" value={form.scope} onChange={(event) => setForm((current) => ({ ...current, scope: event.target.value }))} />
          <Input aria-label="Retention days" type="number" min={1} max={365} value={form.retention_days} onChange={(event) => setForm((current) => ({ ...current, retention_days: event.target.value }))} />
        </div>
        <DialogFooter className="gap-2">
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button disabled={!canGenerate || createRun.isPending} onClick={submit}>Create run</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function RunsTable({ runs, loading, onSelect, compact = false }: { runs: ReportRun[]; loading?: boolean; onSelect?: (run: ReportRun) => void; compact?: boolean }) {
  return (
    <Card className="glass-card overflow-hidden">
      <div className="p-4 border-b border-white/5 bg-black/20"><CardTitle className="text-neutral-100 text-base">Report runs</CardTitle></div>
      <DataTable headers={compact ? ['Status', 'Type', 'Manifest', 'Updated'] : ['Status', 'Type', 'Template', 'Artifacts', 'Manifest hash', 'Expires', 'Actions']} loading={loading} emptyTitle="No report runs" emptyDescription="Generated report runs will appear here.">
        {runs.map((run) => (
          <tr key={run.id} className="hover:bg-white/[0.02]">
            <td className="p-4"><LabelBadge value={run.status} /></td>
            <td className="p-4 text-neutral-300">{labelText(String(run.filters?.report_type || run.filters?.scope || 'trust overview'))}</td>
            {!compact && <td className="p-4 font-mono text-xs text-neutral-500">{safeExportText(run.template_id || '-')}</td>}
            {!compact && <td className="p-4 text-neutral-300">{run.artifacts.length}</td>}
            <td className="p-4 font-mono text-xs text-neutral-400 max-w-[260px] truncate">{safeExportText(run.manifest_hash || '-')}</td>
            <td className="p-4 text-neutral-400 text-xs">{dateText(run.completed_at || run.started_at)}</td>
            {!compact && <td className="p-4"><Button size="sm" variant="outline" onClick={() => onSelect?.(run)}>Detail</Button></td>}
          </tr>
        ))}
      </DataTable>
    </Card>
  );
}

function RunDetailSheet({ run, onClose }: { run: ReportRun | null; onClose: () => void }) {
  return (
    <Sheet open={!!run} onOpenChange={(open) => !open && onClose()}>
      <SheetContent className="w-full sm:max-w-2xl bg-[#0a0a0a] border-white/10 text-neutral-100 overflow-y-auto">
        {run && (
          <>
            <SheetHeader className="border-b border-white/5">
              <SheetTitle>Report run detail</SheetTitle>
              <SheetDescription className="font-mono text-xs">{run.id}</SheetDescription>
            </SheetHeader>
            <div className="p-4 space-y-4">
              <div className="flex flex-wrap gap-2"><LabelBadge value={run.status} /><Badge variant="outline" className="border-white/10 text-neutral-300">metadata only</Badge></div>
              <div className="grid md:grid-cols-2 gap-3">
                <Info label="Manifest hash" value={run.manifest_hash || '-'} mono />
                <Info label="Template" value={run.template_id || '-'} mono />
                <Info label="Requested by" value={run.requested_by || '-'} mono />
                <Info label="Expires" value={dateText(run.expires_at)} />
                <Info label="Started" value={dateText(run.started_at)} />
                <Info label="Completed" value={dateText(run.completed_at)} />
              </div>
              {run.failed_reason && <RoleNotice text={`Failure reason: ${safeExportText(run.failed_reason)}`} />}
              <ArtifactMiniList artifacts={run.artifacts} />
              <Info label="Filters" value={JSON.stringify(run.filters || {}, null, 2)} mono />
            </div>
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}

function ArtifactMiniList({ artifacts }: { artifacts: ReportArtifactMetadata[] }) {
  if (artifacts.length === 0) return <Info label="Artifacts" value="No artifact metadata linked" />;
  return (
    <section className="space-y-2">
      <h3 className="text-xs uppercase tracking-wider text-neutral-500">Artifacts</h3>
      {artifacts.map((artifact) => (
        <div key={artifact.id} className="rounded-md border border-white/10 bg-white/[0.02] p-3 text-sm text-neutral-300">
          <div className="flex flex-wrap gap-2 mb-2"><LabelBadge value={artifact.artifact_type} /><LabelBadge value={artifact.sanitization_version} /></div>
          <div className="font-mono text-xs break-words">content hash {safeExportText(artifact.content_hash)}</div>
          <div className="text-xs text-neutral-500 mt-1">expires {dateText(artifact.expires_at)}</div>
        </div>
      ))}
    </section>
  );
}

function ArtifactsView({ canDownload, canShare }: { canDownload: boolean; canShare: boolean }) {
  const [selected, setSelected] = useState<ReportArtifactMetadata | null>(null);
  const [downloaded, setDownloaded] = useState<ReportArtifactDownload | null>(null);
  const [createdShare, setCreatedShare] = useState<{ token?: string; artifact_id: string; expires_at: string } | null>(null);
  const [filters, setFilters] = useState({ artifact_type: '', run_id: '' });
  const artifactsQuery = useReportArtifacts({ ...filters, skip: 0, limit: PAGE_SIZE });
  const downloadArtifact = useDownloadReportArtifact();
  const createShare = useCreateShareLink();
  const shareLinksQuery = useShareLinks({ skip: 0, limit: PAGE_SIZE });
  const revokeShare = useRevokeShareLink();
  const handleDownload = async (artifact: ReportArtifactMetadata) => {
    try {
      const result = await downloadArtifact.mutateAsync(artifact.id);
      setDownloaded(result);
      toast.success('Sanitized artifact metadata loaded');
    } catch (err: unknown) {
      toast.error(errorMessage(err));
    }
  };
  const handleShare = async (artifact: ReportArtifactMetadata) => {
    try {
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
      const result = await createShare.mutateAsync({ artifact_id: artifact.id, expires_at: expiresAt, max_downloads: 5 });
      setCreatedShare({ token: result.token, artifact_id: result.artifact_id, expires_at: result.expires_at });
      toast.success('Trust Center share link created');
    } catch (err: unknown) {
      toast.error(errorMessage(err));
    }
  };
  return (
    <ReportShell view="artifacts">
      {!canDownload && <RoleNotice text="Artifact download controls are hidden for this role. Metadata remains visible where permitted." />}
      {!canShare && <RoleNotice text="Shareable Trust Center controls require auditor, admin, or owner role." />}
      <Card className="glass-card">
        <CardContent className="p-4">
          <div className="grid md:grid-cols-2 gap-3">
            <FilterSelect label="Artifact type" value={filters.artifact_type} onChange={(value) => setFilters((current) => ({ ...current, artifact_type: value }))} options={[['', 'All types'], ['json', 'JSON'], ['evidence_package_json', 'Evidence package JSON'], ['trust_report_json', 'Trust report JSON']]} />
            <Input aria-label="Run ID" placeholder="run_id" value={filters.run_id} onChange={(event) => setFilters((current) => ({ ...current, run_id: event.target.value }))} className="bg-black/40 border-white/10 text-neutral-100 font-mono" />
          </div>
        </CardContent>
      </Card>
      <ArtifactsTable artifacts={artifactsQuery.data?.items || []} loading={artifactsQuery.isLoading} onSelect={setSelected} onDownload={handleDownload} onShare={handleShare} canDownload={canDownload} canShare={canShare} />
      <ShareLinksTable links={shareLinksQuery.data?.items || []} loading={shareLinksQuery.isLoading} onRevoke={(id) => revokeShare.mutate(id)} canShare={canShare} />
      <ArtifactDetailSheet artifact={selected} onClose={() => setSelected(null)} />
      <DownloadMetadataSheet result={downloaded} onClose={() => setDownloaded(null)} />
      <ShareLinkSheet result={createdShare} onClose={() => setCreatedShare(null)} />
    </ReportShell>
  );
}

function ArtifactsTable({
  artifacts,
  loading,
  onSelect,
  onDownload,
  onShare,
  canDownload = false,
  canShare = false,
}: {
  artifacts: ReportArtifactMetadata[];
  loading?: boolean;
  onSelect?: (artifact: ReportArtifactMetadata) => void;
  onDownload?: (artifact: ReportArtifactMetadata) => void;
  onShare?: (artifact: ReportArtifactMetadata) => void;
  canDownload?: boolean;
  canShare?: boolean;
}) {
  return (
    <Card className="glass-card overflow-hidden">
      <div className="p-4 border-b border-white/5 bg-black/20"><CardTitle className="text-neutral-100 text-base">Artifact metadata</CardTitle></div>
      <DataTable headers={['Type', 'Content hash', 'Manifest hash', 'Size', 'Sanitizer', 'Expires', 'Actions']} loading={loading} emptyTitle="No artifacts" emptyDescription="Artifact metadata appears after report generation.">
        {artifacts.map((artifact) => (
          <tr key={artifact.id} className="hover:bg-white/[0.02]">
            <td className="p-4"><LabelBadge value={artifact.artifact_type} /></td>
            <td className="p-4 font-mono text-xs text-neutral-400 max-w-[220px] truncate">{safeExportText(artifact.content_hash)}</td>
            <td className="p-4 font-mono text-xs text-neutral-400 max-w-[220px] truncate">{safeExportText(artifact.manifest_hash || '-')}</td>
            <td className="p-4 text-neutral-300">{artifact.size_bytes.toLocaleString()} bytes</td>
            <td className="p-4"><LabelBadge value={artifact.sanitization_version} /></td>
            <td className="p-4 text-neutral-400 text-xs">{dateText(artifact.expires_at)}</td>
            <td className="p-4">
              <div className="flex flex-wrap gap-2">
                {onSelect && <Button size="sm" variant="outline" onClick={() => onSelect(artifact)}>Manifest</Button>}
                {onDownload && canDownload && <Button size="sm" variant="outline" onClick={() => onDownload(artifact)}>Download</Button>}
                {onShare && canShare && <Button size="sm" variant="outline" onClick={() => onShare(artifact)}><Share2 className="h-3.5 w-3.5 mr-1" />Share</Button>}
              </div>
            </td>
          </tr>
        ))}
      </DataTable>
    </Card>
  );
}

function ShareLinksTable({
  links,
  loading,
  onRevoke,
  canShare,
}: {
  links: Array<{ id: string; artifact_id: string; expires_at: string; revoked_at?: string | null; max_downloads: number }>;
  loading?: boolean;
  onRevoke: (id: string) => void;
  canShare: boolean;
}) {
  return (
    <Card className="glass-card overflow-hidden">
      <div className="p-4 border-b border-white/5 bg-black/20 flex items-center gap-2">
        <Share2 className="h-4 w-4 text-blue-400" />
        <CardTitle className="text-neutral-100 text-base">Shareable Trust Center links</CardTitle>
      </div>
      <DataTable headers={['Status', 'Artifact', 'Max downloads', 'Expires', 'Actions']} loading={loading} emptyTitle="No share links" emptyDescription="Create a share link from a sanitized artifact to share Trust Center evidence externally.">
        {links.map((link) => (
          <tr key={link.id} className="hover:bg-white/[0.02]">
            <td className="p-4"><LabelBadge value={link.revoked_at ? 'revoked' : 'active'} /></td>
            <td className="p-4 font-mono text-xs text-neutral-400 max-w-[220px] truncate">{safeExportText(link.artifact_id)}</td>
            <td className="p-4 text-neutral-300">{link.max_downloads}</td>
            <td className="p-4 text-neutral-400 text-xs">{dateText(link.expires_at)}</td>
            <td className="p-4">
              <Button size="sm" variant="outline" disabled={!canShare || !!link.revoked_at} onClick={() => onRevoke(link.id)}>Revoke</Button>
            </td>
          </tr>
        ))}
      </DataTable>
    </Card>
  );
}

function ShareLinkSheet({ result, onClose }: { result: { token?: string; artifact_id: string; expires_at: string } | null; onClose: () => void }) {
  const shareUrl = result?.token && typeof window !== 'undefined' ? `${window.location.origin}/trust/shared/${encodeURIComponent(result.token)}` : '';
  const copyShareUrl = async () => {
    if (!shareUrl) return;
    await navigator.clipboard.writeText(shareUrl);
    toast.success('Share URL copied');
  };
  return (
    <Sheet open={!!result} onOpenChange={(open) => !open && onClose()}>
      <SheetContent className="w-full sm:max-w-xl bg-[#0a0a0a] border-white/10 text-neutral-100 overflow-y-auto">
        {result && (
          <>
            <SheetHeader className="border-b border-white/5">
              <SheetTitle>Trust Center share link created</SheetTitle>
              <SheetDescription className="font-mono text-xs">{result.artifact_id}</SheetDescription>
            </SheetHeader>
            <div className="p-4 space-y-4">
              <div className="rounded-md border border-amber-500/20 bg-amber-500/10 px-4 py-3 text-sm text-amber-200">
                Copy this external URL now. The console only displays it immediately after creation.
              </div>
              <Info label="Share URL" value={shareUrl || 'not returned'} mono />
              <Info label="Expires" value={dateText(result.expires_at)} />
              <Button disabled={!shareUrl} onClick={copyShareUrl}>Copy share URL</Button>
            </div>
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}

function ArtifactDetailSheet({ artifact, onClose }: { artifact: ReportArtifactMetadata | null; onClose: () => void }) {
  const manifestQuery = useReportArtifactManifest(artifact?.id);
  const manifest = manifestQuery.data;
  return (
    <Sheet open={!!artifact} onOpenChange={(open) => !open && onClose()}>
      <SheetContent className="w-full sm:max-w-2xl bg-[#0a0a0a] border-white/10 text-neutral-100 overflow-y-auto">
        {artifact && (
          <>
            <SheetHeader className="border-b border-white/5">
              <SheetTitle>Artifact manifest</SheetTitle>
              <SheetDescription className="font-mono text-xs">{artifact.id}</SheetDescription>
            </SheetHeader>
            <div className="p-4 space-y-4">
              <div className="grid md:grid-cols-2 gap-3">
                <Info label="Content hash" value={artifact.content_hash} mono />
                <Info label="Manifest hash" value={artifact.manifest_hash || manifest?.manifest_hash || '-'} mono />
                <Info label="Size" value={`${artifact.size_bytes.toLocaleString()} bytes`} />
                <Info label="Sanitization" value={artifact.sanitization_version} />
              </div>
              <ManifestBlock manifest={manifest} loading={manifestQuery.isLoading} />
            </div>
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}

function ManifestBlock({ manifest, loading }: { manifest?: ExportManifest | null; loading?: boolean }) {
  if (loading) return <TableSkeleton columns={2} rows={4} />;
  if (!manifest) return <Info label="Manifest" value="Manifest metadata not returned" />;
  return (
    <div className="space-y-3">
      <Info label="Hash algorithm" value={manifest.hash_algorithm} />
      <Info label="Manifest hash" value={manifest.manifest_hash} mono />
      <pre className="max-h-80 overflow-auto rounded-md border border-white/10 bg-black/50 p-3 text-xs text-neutral-300 whitespace-pre-wrap break-words">{safeExportText(JSON.stringify(manifest.manifest_json || {}, null, 2))}</pre>
    </div>
  );
}

function DownloadMetadataSheet({ result, onClose }: { result: ReportArtifactDownload | null; onClose: () => void }) {
  return (
    <Sheet open={!!result} onOpenChange={(open) => !open && onClose()}>
      <SheetContent className="w-full sm:max-w-2xl bg-[#0a0a0a] border-white/10 text-neutral-100 overflow-y-auto">
        {result && (
          <>
            <SheetHeader className="border-b border-white/5">
              <SheetTitle>Sanitized download metadata</SheetTitle>
              <SheetDescription className="font-mono text-xs">{result.artifact_id}</SheetDescription>
            </SheetHeader>
            <div className="p-4 space-y-4">
              <div className="rounded-md border border-blue-500/20 bg-blue-500/10 px-4 py-3 text-sm text-blue-200">
                Download response received. The UI displays watermark and manifest metadata only; raw report body preview remains hidden.
              </div>
              <div className="grid md:grid-cols-2 gap-3">
                <Info label="Artifact" value={result.artifact_id} mono />
                <Info label="Tenant" value={result.tenant_id} mono />
                <Info label="Requester" value={result.requester_id || result.external_share_id || '-'} mono />
                <Info label="Downloaded" value={dateText(result.downloaded_at)} />
                <Info label="Manifest hash" value={result.manifest_hash || '-'} mono />
                <Info label="Content type" value={result.content_type} />
              </div>
              <pre className="max-h-80 overflow-auto rounded-md border border-white/10 bg-black/50 p-3 text-xs text-neutral-300 whitespace-pre-wrap break-words">{safeExportText(JSON.stringify(result.watermark || {}, null, 2))}</pre>
            </div>
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}

function EvidencePackagesView({ canGenerate }: { canGenerate: boolean }) {
  const [selected, setSelected] = useState<ReportRun | null>(null);
  const packagesQuery = useEvidencePackages({ skip: 0, limit: PAGE_SIZE });
  return (
    <ReportShell view="evidence-packages">
      {!canGenerate && <RoleNotice text="Evidence package generation is disabled for this role." />}
      <EvidencePackageBuilder canGenerate={canGenerate} onCreated={(result) => setSelected(result.run)} />
      <RunsTable runs={packagesQuery.data?.items || []} loading={packagesQuery.isLoading} onSelect={setSelected} />
      <RunDetailSheet run={selected} onClose={() => setSelected(null)} />
    </ReportShell>
  );
}

function EvidencePackageBuilder({ canGenerate, onCreated }: { canGenerate: boolean; onCreated: (result: { run: ReportRun }) => void }) {
  const createPackage = useCreateEvidencePackage();
  const [form, setForm] = useState({
    framework_id: '',
    control_ids: '',
    date_from: '',
    date_to: '',
    evidence_freshness_days: '90',
    include_findings: true,
    include_remediation: true,
    retention_days: '90',
  });
  const submit = async () => {
    try {
      const result = await createPackage.mutateAsync({
        framework_id: form.framework_id || null,
        control_ids: form.control_ids.split(',').map((item) => item.trim()).filter(Boolean),
        date_from: form.date_from ? new Date(form.date_from).toISOString() : null,
        date_to: form.date_to ? new Date(form.date_to).toISOString() : null,
        evidence_freshness_days: Number(form.evidence_freshness_days) || null,
        include_findings: form.include_findings,
        include_remediation: form.include_remediation,
        output_format: 'json',
        retention_days: Number(form.retention_days) || 90,
      });
      toast.success('Evidence package created');
      onCreated(result);
    } catch (err: unknown) {
      toast.error(errorMessage(err));
    }
  };
  return (
    <Card className="glass-card">
      <CardContent className="p-4 space-y-4">
        <div className="flex items-center gap-2"><FileJson className="h-4 w-4 text-blue-400" /><CardTitle className="text-neutral-100 text-base">Evidence package builder</CardTitle><Badge variant="outline" className="border-white/10 text-neutral-300">JSON only</Badge></div>
        <div className="grid md:grid-cols-4 gap-3">
          <Input aria-label="Framework" placeholder="framework UUID" value={form.framework_id} onChange={(event) => setForm((current) => ({ ...current, framework_id: event.target.value }))} className="bg-black/40 border-white/10 text-neutral-100 font-mono" />
          <Input aria-label="Controls" placeholder="control UUIDs, comma separated" value={form.control_ids} onChange={(event) => setForm((current) => ({ ...current, control_ids: event.target.value }))} className="bg-black/40 border-white/10 text-neutral-100 font-mono" />
          <Input aria-label="Date from" type="datetime-local" value={form.date_from} onChange={(event) => setForm((current) => ({ ...current, date_from: event.target.value }))} className="bg-black/40 border-white/10 text-neutral-100" />
          <Input aria-label="Date to" type="datetime-local" value={form.date_to} onChange={(event) => setForm((current) => ({ ...current, date_to: event.target.value }))} className="bg-black/40 border-white/10 text-neutral-100" />
          <Input aria-label="Evidence freshness days" type="number" min={1} max={365} value={form.evidence_freshness_days} onChange={(event) => setForm((current) => ({ ...current, evidence_freshness_days: event.target.value }))} className="bg-black/40 border-white/10 text-neutral-100" />
          <Input aria-label="Package retention days" type="number" min={1} max={365} value={form.retention_days} onChange={(event) => setForm((current) => ({ ...current, retention_days: event.target.value }))} className="bg-black/40 border-white/10 text-neutral-100" />
          <label className="flex items-center gap-2 text-sm text-neutral-300"><input type="checkbox" checked={form.include_findings} onChange={(event) => setForm((current) => ({ ...current, include_findings: event.target.checked }))} /> Include findings</label>
          <label className="flex items-center gap-2 text-sm text-neutral-300"><input type="checkbox" checked={form.include_remediation} onChange={(event) => setForm((current) => ({ ...current, include_remediation: event.target.checked }))} /> Include remediation</label>
        </div>
        <div className="flex justify-end">
          <Button disabled={!canGenerate || createPackage.isPending} onClick={submit}><PackageCheck className="h-4 w-4 mr-2" />Create evidence package</Button>
        </div>
      </CardContent>
    </Card>
  );
}

function AccessLogsView({ canViewAccessLogs }: { canViewAccessLogs: boolean }) {
  const [filters, setFilters] = useState({ action: '', artifact_id: '' });
  const logsQuery = useReportAccessLogs({ ...filters, skip: 0, limit: PAGE_SIZE });
  if (!canViewAccessLogs) {
    return (
      <ReportShell view="access-logs">
        <RoleNotice text="Access log visibility requires auditor, admin, or owner role." />
      </ReportShell>
    );
  }
  return (
    <ReportShell view="access-logs">
      <Card className="glass-card">
        <CardContent className="p-4">
          <div className="grid md:grid-cols-2 gap-3">
            <FilterSelect label="Action" value={filters.action} onChange={(value) => setFilters((current) => ({ ...current, action: value }))} options={[['', 'All actions'], ['created', 'Created'], ['viewed', 'Viewed'], ['generated', 'Generated']]} />
            <Input aria-label="Artifact ID" placeholder="artifact_id" value={filters.artifact_id} onChange={(event) => setFilters((current) => ({ ...current, artifact_id: event.target.value }))} className="bg-black/40 border-white/10 text-neutral-100 font-mono" />
          </div>
        </CardContent>
      </Card>
      <Card className="glass-card overflow-hidden">
        <div className="p-4 border-b border-white/5 bg-black/20"><CardTitle className="text-neutral-100 text-base">Report access logs</CardTitle></div>
        <DataTable headers={['Action', 'Artifact', 'Actor', 'External ref', 'IP hash', 'User-agent hash', 'Created']} loading={logsQuery.isLoading} emptyTitle="No access logs" emptyDescription="Metadata-only report access events appear here.">
          {(logsQuery.data?.items || []).map((log: ReportAccessLog) => (
            <tr key={log.id} className="hover:bg-white/[0.02]">
              <td className="p-4"><LabelBadge value={log.action} /></td>
              <td className="p-4 font-mono text-xs text-neutral-400">{safeExportText(log.artifact_id)}</td>
              <td className="p-4 font-mono text-xs text-neutral-400">{safeExportText(log.actor_user_id || '-')}</td>
              <td className="p-4 font-mono text-xs text-neutral-400">{safeExportText(log.external_share_id || '-')}</td>
              <td className="p-4 font-mono text-xs text-neutral-400">{safeExportText(log.ip_hash || '-')}</td>
              <td className="p-4 font-mono text-xs text-neutral-400">{safeExportText(log.user_agent_hash || '-')}</td>
              <td className="p-4 text-neutral-400 text-xs">{dateText(log.created_at)}</td>
            </tr>
          ))}
        </DataTable>
      </Card>
    </ReportShell>
  );
}

export function NotificationCenter() {
  const [unreadOnly, setUnreadOnly] = useState(false);
  const [severity, setSeverity] = useState('');
  const notificationsQuery = useTrustNotifications({ unread_only: unreadOnly, severity, skip: 0, limit: PAGE_SIZE });
  const unreadQuery = useNotificationUnreadCount();
  const markRead = useMarkTrustNotificationRead();
  const markAllRead = useMarkAllTrustNotificationsRead();
  const items = notificationsQuery.data?.items || [];
  const handleMarkRead = async (notification: TrustNotification) => {
    try {
      await markRead.mutateAsync(notification.id);
      toast.success('Notification marked read');
    } catch (err: unknown) {
      toast.error(errorMessage(err));
    }
  };
  const handleMarkAllRead = async () => {
    try {
      await markAllRead.mutateAsync();
      toast.success('Notifications marked read');
    } catch (err: unknown) {
      toast.error(errorMessage(err));
    }
  };

  return (
    <div className="space-y-6 max-w-[1600px] mx-auto pb-10">
      <div className="flex flex-col xl:flex-row items-start xl:items-end justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-neutral-100">Notification Center</h2>
          <p className="text-sm text-neutral-400 mt-1">In-app trust, report, remediation, evidence, and integration notifications.</p>
        </div>
        <Button variant="outline" onClick={handleMarkAllRead} disabled={markAllRead.isPending || (unreadQuery.data?.unread || 0) === 0}>
          <CheckCircle2 className="h-4 w-4 mr-2" />Mark all read
        </Button>
      </div>
      <div className="rounded-md border border-blue-500/20 bg-blue-500/10 px-4 py-3 text-sm text-blue-200">
        Sanitized event summaries only. Raw provider payloads, credentials, Vault references, raw IP values, and legal guarantee copy are intentionally absent.
      </div>
      <div className="grid gap-4 md:grid-cols-3">
        <Metric label="Unread" value={unreadQuery.data?.unread ?? 0} hint="Current tenant notifications" />
        <Metric label="Loaded" value={items.length} hint="Visible notifications" />
        <Metric label="Total" value={notificationsQuery.data?.total ?? 0} hint="Filtered notification rows" />
      </div>
      <Card className="glass-card">
        <CardContent className="p-4">
          <div className="grid md:grid-cols-3 gap-3">
            <label className="flex items-center gap-2 text-sm text-neutral-300">
              <input type="checkbox" checked={unreadOnly} onChange={(event) => setUnreadOnly(event.target.checked)} />
              Unread only
            </label>
            <FilterSelect label="Severity" value={severity} onChange={setSeverity} options={[['', 'All severities'], ['info', 'Info'], ['warning', 'Warning'], ['error', 'Error'], ['critical', 'Critical']]} />
          </div>
        </CardContent>
      </Card>
      <Card className="glass-card overflow-hidden">
        <div className="p-4 border-b border-white/5 bg-black/20 flex items-center gap-2">
          <Bell className="h-4 w-4 text-blue-400" />
          <CardTitle className="text-neutral-100 text-base">Notifications</CardTitle>
        </div>
        <DataTable headers={['Status', 'Severity', 'Type', 'Message', 'Resource', 'Created', 'Actions']} loading={notificationsQuery.isLoading} emptyTitle="No notifications" emptyDescription="Notifications appear when trust, report, remediation, evidence, or integration events need review.">
          {items.map((notification) => (
            <tr key={notification.id} className="hover:bg-white/[0.02] align-top">
              <td className="p-4"><LabelBadge value={notification.read_at ? 'read' : 'unread'} /></td>
              <td className="p-4"><LabelBadge value={notification.severity} /></td>
              <td className="p-4 text-neutral-300">{labelText(notification.type)}</td>
              <td className="p-4 min-w-[280px]">
                <div className="text-neutral-100 font-medium">{safeExportText(notification.title)}</div>
                <div className="text-neutral-400 text-xs mt-1">{safeExportText(notification.body)}</div>
              </td>
              <td className="p-4">
                <div className="text-neutral-300">{labelText(notification.resource_type || '-')}</div>
                <div className="font-mono text-xs text-neutral-500 max-w-[180px] truncate">{safeExportText(notification.resource_id || '-')}</div>
              </td>
              <td className="p-4 text-neutral-400 text-xs whitespace-nowrap">{dateText(notification.created_at)}</td>
              <td className="p-4">
                <Button size="sm" variant="outline" disabled={!!notification.read_at || markRead.isPending} onClick={() => handleMarkRead(notification)}>
                  Mark read
                </Button>
              </td>
            </tr>
          ))}
        </DataTable>
      </Card>
    </div>
  );
}

export function TrustConsole({ view = 'overview' }: { view?: TrustView }) {
  if (view === 'overview') return <TrustOverviewView />;
  if (view === 'activity') return <ActivityTimelineView />;
  return <PostureDetail kind={view} />;
}

export function ReportConsole({ view = 'overview' }: { view?: ReportView }) {
  const { user } = useAuth();
  const permissions = useMemo(() => permissionsFor(user), [user]);
  if (!permissions.canViewReports) return <NoReportAccess />;
  if (view === 'templates') return <TemplatesView canManageTemplates={permissions.canManageTemplates} />;
  if (view === 'runs') return <RunsView canGenerate={permissions.canGenerate} />;
  if (view === 'artifacts') return <ArtifactsView canDownload={permissions.canDownload} canShare={permissions.canShare} />;
  if (view === 'evidence-packages') return <EvidencePackagesView canGenerate={permissions.canGenerate} />;
  if (view === 'access-logs') return <AccessLogsView canViewAccessLogs={permissions.canViewAccessLogs} />;
  return <ReportOverviewView canGenerate={permissions.canGenerate} canDownload={permissions.canDownload} />;
}
