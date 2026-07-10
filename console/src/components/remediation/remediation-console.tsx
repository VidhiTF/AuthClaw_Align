"use client";

import Link from 'next/link';
import { useMemo, useState } from 'react';
import {
  Ban,
  Clock,
  FileText,
  Filter,
  LockKeyhole,
  RefreshCw,
  RotateCcw,
  ShieldCheck,
  Workflow,
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
  RemediationApproval,
  RemediationDryRunResult,
  RemediationExecutionJob,
  RemediationPlan,
  RemediationPlanDetail,
  RemediationVerificationResult,
  useApproveRemediationApproval,
  useGenerateRemediationPlan,
  useRejectRemediationApproval,
  useRemediationApprovals,
  useRemediationDryRuns,
  useRemediationJobs,
  useRemediationPlan,
  useRemediationPlans,
  useRemediationVerificationResults,
  useRequestRemediationApproval,
  useRevokeRemediationApproval,
  useValidateRemediationPlan,
} from '@/hooks/use-data';

type RemediationView = 'overview' | 'plans' | 'plan-detail' | 'approvals' | 'jobs';
type ActionKind = 'request' | 'approve' | 'reject' | 'revoke';

type RoleAwareUser = {
  role?: string;
  role_name?: string;
  roles?: string[];
};

type ApiError = {
  response?: { data?: { detail?: string } };
  message?: string;
};

const PAGE_SIZE = 25;

const navItems: Array<{ view: RemediationView; label: string; href: string; icon: typeof ShieldCheck }> = [
  { view: 'overview', label: 'Overview', href: '/remediation', icon: ShieldCheck },
  { view: 'plans', label: 'Plans', href: '/remediation/plans', icon: FileText },
  { view: 'approvals', label: 'Approvals', href: '/remediation/approvals', icon: LockKeyhole },
  { view: 'jobs', label: 'Jobs', href: '/remediation/jobs', icon: Workflow },
];

function rolesFor(user: unknown) {
  const roleUser = (user || {}) as RoleAwareUser;
  const roles = [
    roleUser.role,
    roleUser.role_name,
    ...(Array.isArray(roleUser.roles) ? roleUser.roles : []),
  ].filter((role): role is string => typeof role === 'string' && role.length > 0).map((role) => role.toLowerCase());
  return roles;
}

function hasAnyRole(user: unknown, allowed: string[]) {
  return rolesFor(user).some((role) => allowed.includes(role));
}

function errorMessage(error: unknown) {
  const apiError = error as ApiError;
  return apiError?.response?.data?.detail || apiError?.message || 'Request failed';
}

function safeText(value: unknown) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/raw_provider_payload/gi, '[redacted-source]')
    .replace(/(token|secret|password|credential|api[_-]?key)\s*[:=]\s*[^,\s}]+/gi, '$1=[redacted]')
    .replace(/ghp_[a-z0-9_]+/gi, '[redacted-token]')
    .replace(/AKIA[0-9A-Z]+/g, '[redacted-key]');
}

function dateText(value?: string | null) {
  if (!value) return 'Not recorded';
  return new Date(value).toLocaleString();
}

function labelText(value?: string | null) {
  return safeText(value || 'unknown').replaceAll('_', ' ');
}

function riskTone(value?: string | null) {
  switch (value) {
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

function statusTone(value?: string | null) {
  switch (value) {
    case 'plan_validated':
    case 'approved':
      return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
    case 'approval_requested':
    case 'pending':
      return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
    case 'expired':
    case 'rejected':
    case 'revoked':
      return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
    case 'disabled':
      return 'bg-neutral-800 text-neutral-400 border-neutral-700';
    default:
      return 'bg-white/5 text-neutral-300 border-white/10';
  }
}

function passTone(value: boolean) {
  return value ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 'bg-red-500/10 text-red-400 border-red-500/20';
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
      <div className={`text-neutral-300 break-words ${mono ? 'font-mono text-xs' : 'text-sm'}`}>{safeText(value || '-')}</div>
    </div>
  );
}

function Metric({ label, value, hint, tone = 'text-neutral-100' }: { label: string; value: string | number; hint: string; tone?: string }) {
  return (
    <Card className="glass-card">
      <CardContent className="p-4">
        <div className="text-xs uppercase tracking-wider text-neutral-500">{label}</div>
        <div className={`mt-3 text-3xl font-semibold ${tone}`}>{value}</div>
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

function ConsoleShell({
  view,
  children,
}: {
  view: RemediationView;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-6 max-w-[1600px] mx-auto pb-10">
      <div className="flex flex-col xl:flex-row items-start xl:items-end justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-neutral-100">Remediation Console</h2>
          <p className="text-sm text-neutral-400 mt-1">Draft remediation plans, validation results, HITL approvals, safe dry-runs, controlled simulated/no-op execution, and verification visibility.</p>
        </div>
        <div className="flex flex-wrap gap-2">
          {navItems.map((item) => {
            const Icon = item.icon;
            const active = view === item.view || (view === 'plan-detail' && item.view === 'plans');
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
        Only safe documentation, no-op, static-validation, and simulated execution can be represented. Real cloud, GitHub, Terraform, shell mutation, credentials, and raw provider payloads remain blocked.
      </div>

      {children}
    </div>
  );
}

function latestPolicyCheck(plan?: RemediationPlanDetail | null) {
  return [...(plan?.policy_checks || [])].sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)))[0];
}

function latestApproval(plan?: RemediationPlanDetail | null) {
  return [...(plan?.approvals || [])].sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)))[0];
}

function validationState(plan: RemediationPlan) {
  if (plan.status === 'plan_validated' || plan.status === 'approval_requested' || plan.status === 'approved') return 'validated';
  if (plan.status === 'rejected' || plan.status === 'expired' || plan.status === 'failed') return 'blocked';
  return 'validation required';
}

function approvalState(plan: RemediationPlan) {
  if (plan.status === 'approval_requested') return 'approval required';
  if (plan.status === 'approved') return 'approved';
  if (plan.status === 'rejected') return 'rejected';
  return 'not requested';
}

function roleCanWrite(user: unknown) {
  return hasAnyRole(user, ['owner', 'admin', 'operator', 'analyst', 'security_admin']);
}

function roleCanApprove(user: unknown) {
  return hasAnyRole(user, ['owner', 'admin', 'operator', 'analyst', 'security_admin']);
}

function roleCanRevoke(user: unknown) {
  return hasAnyRole(user, ['owner', 'admin', 'security_admin']);
}

function ActionDialog({
  kind,
  plan,
  approval,
  open,
  onOpenChange,
}: {
  kind: ActionKind | null;
  plan?: RemediationPlan | RemediationPlanDetail | null;
  approval?: RemediationApproval | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const [reason, setReason] = useState('');
  const [mfaVerified, setMfaVerified] = useState(false);
  const requestApproval = useRequestRemediationApproval();
  const approve = useApproveRemediationApproval();
  const reject = useRejectRemediationApproval();
  const revoke = useRevokeRemediationApproval();
  const targetId = approval?.id || plan?.id || '';
  const requiresReason = kind === 'approve' || kind === 'reject' || kind === 'revoke';
  const disabled = (requiresReason && !reason.trim()) || requestApproval.isPending || approve.isPending || reject.isPending || revoke.isPending;

  const close = () => {
    setReason('');
    setMfaVerified(false);
    onOpenChange(false);
  };

  const submit = async () => {
    try {
      if (kind === 'request' && plan) {
        await requestApproval.mutateAsync({ planId: plan.id, reason: reason || undefined });
        toast.success('Approval requested');
      } else if (kind === 'approve' && approval) {
        await approve.mutateAsync({ id: approval.id, approval_reason: reason, mfa_verified: mfaVerified });
        toast.success('Approval recorded');
      } else if (kind === 'reject' && approval) {
        await reject.mutateAsync({ id: approval.id, rejection_reason: reason });
        toast.success('Approval rejected');
      } else if (kind === 'revoke' && approval) {
        await revoke.mutateAsync({ id: approval.id, reason });
        toast.success('Approval revoked');
      }
      close();
    } catch (err: unknown) {
      toast.error(errorMessage(err));
    }
  };

  const title = kind === 'request' ? 'Request remediation approval' : `${labelText(kind)} remediation approval`;
  return (
    <Dialog open={open} onOpenChange={(next) => { if (!next) close(); else onOpenChange(next); }}>
      <DialogContent className="max-w-lg bg-[#0a0a0a] border-white/10 text-neutral-100">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>Approval records review intent only. It does not execute changes or start any provider mutation.</DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <Info label="Target" value={targetId} mono />
          <div className="space-y-1">
            <label className="text-[10px] uppercase tracking-wider text-neutral-500">Reason</label>
            <textarea
              aria-label="Reason"
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              rows={4}
              className="w-full rounded-md bg-black/40 border border-white/10 text-neutral-100 px-3 py-2 text-sm"
              placeholder={requiresReason ? 'Required before this action' : 'Optional context for reviewers'}
            />
          </div>
          {kind === 'approve' && (
            <label className="flex items-center gap-2 text-sm text-neutral-300">
              <input type="checkbox" checked={mfaVerified} onChange={(event) => setMfaVerified(event.target.checked)} className="h-4 w-4" />
              MFA verified for elevated approval
            </label>
          )}
          <div className="rounded-md border border-blue-500/20 bg-blue-500/10 px-3 py-2 text-xs text-blue-200">
            Backend approval policy remains source of truth for RBAC, self-approval, expiry, replay, and hash checks.
          </div>
        </div>
        <DialogFooter className="gap-2">
          <Button variant="outline" onClick={close}>Cancel</Button>
          <Button onClick={submit} disabled={disabled}>{kind === 'request' ? 'Request approval' : labelText(kind)}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function GeneratePlanDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const [sourceType, setSourceType] = useState<'finding' | 'gap' | 'recommendation'>('finding');
  const [sourceId, setSourceId] = useState('');
  const generate = useGenerateRemediationPlan();

  const close = () => {
    setSourceType('finding');
    setSourceId('');
    onOpenChange(false);
  };

  const submit = async () => {
    try {
      await generate.mutateAsync({ source_type: sourceType, source_id: sourceId });
      toast.success('Draft plan generated');
      close();
    } catch (err: unknown) {
      toast.error(errorMessage(err));
    }
  };

  return (
    <Dialog open={open} onOpenChange={(next) => { if (!next) close(); else onOpenChange(next); }}>
      <DialogContent className="max-w-lg bg-[#0a0a0a] border-white/10 text-neutral-100">
        <DialogHeader>
          <DialogTitle>Generate draft remediation plan</DialogTitle>
          <DialogDescription>Creates a deterministic non-executing draft from an existing finding, gap, or recommendation.</DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <FilterSelect label="Source type" value={sourceType} onChange={(value) => setSourceType(value as typeof sourceType)} options={[['finding', 'Finding'], ['gap', 'Compliance gap'], ['recommendation', 'Recommendation']]} />
          <div className="space-y-1">
            <label className="text-[10px] uppercase tracking-wider text-neutral-500">Source ID</label>
            <Input aria-label="Source ID" value={sourceId} onChange={(event) => setSourceId(event.target.value)} className="bg-black/40 border-white/10 text-neutral-100 font-mono" />
          </div>
        </div>
        <DialogFooter className="gap-2">
          <Button variant="outline" onClick={close}>Cancel</Button>
          <Button onClick={submit} disabled={!sourceId.trim() || generate.isPending}>Generate draft</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function Overview() {
  const plansQuery = useRemediationPlans({ skip: 0, limit: 100 });
  const approvalsQuery = useRemediationApprovals({ skip: 0, limit: 100 });
  const jobsQuery = useRemediationJobs({ skip: 0, limit: 100 });
  const plans = plansQuery.data?.items || [];
  const approvals = approvalsQuery.data?.items || [];
  const jobs = jobsQuery.data?.items || [];
  const pendingApprovals = approvals.filter((item) => item.status === 'pending');
  const elevatedRisk = plans.filter((plan) => ['high', 'critical'].includes(String(plan.risk_level)));
  const blocked = plans.filter((plan) => ['rejected', 'expired', 'failed'].includes(String(plan.status)));
  const approved = approvals.filter((item) => item.status === 'approved');
  const executing = jobs.filter((job) => job.status === 'executing' || job.status === 'queued');
  const succeeded = jobs.filter((job) => job.status === 'succeeded');
  const failed = jobs.filter((job) => job.status === 'failed' || job.status === 'disabled');

  return (
    <ConsoleShell view="overview">
      <div className="grid gap-4 md:grid-cols-4">
        <Metric label="Plans" value={plansQuery.data?.total ?? plans.length} hint="Draft and reviewed plans" />
        <Metric label="Pending approvals" value={pendingApprovals.length} hint="Waiting for HITL review" tone="text-blue-300" />
        <Metric label="High or critical" value={elevatedRisk.length} hint="Plans requiring careful review" tone="text-orange-300" />
        <Metric label="Blocked or expired" value={blocked.length} hint="Failed validations or closed requests" tone="text-amber-300" />
      </div>

      <WorkflowTracker
        pending={pendingApprovals.length}
        approved={approved.length}
        executing={executing.length}
        succeeded={succeeded.length}
        failed={failed.length}
        loading={approvalsQuery.isLoading || jobsQuery.isLoading}
      />

      <Card className="glass-card">
        <CardContent className="p-4 flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <Ban className="h-5 w-5 text-amber-300" />
            <div>
              <CardTitle className="text-neutral-100 text-base">Controlled safe execution visibility</CardTitle>
              <p className="text-xs text-neutral-400 mt-1">Safe simulated/no-op results can be reviewed. The UI cannot start infrastructure, provider, Terraform, or shell changes.</p>
            </div>
          </div>
          <Link className="text-sm text-blue-300 hover:text-blue-200" href="/remediation/jobs">Review job status</Link>
        </CardContent>
      </Card>

      <div className="grid gap-6 xl:grid-cols-2">
        <RecentPlans plans={plans.slice(0, 6)} loading={plansQuery.isLoading} />
        <RecentApprovals approvals={approvals.slice(0, 6)} loading={approvalsQuery.isLoading} />
      </div>
    </ConsoleShell>
  );
}

function WorkflowTracker({
  pending,
  approved,
  executing,
  succeeded,
  failed,
  loading,
}: {
  pending: number;
  approved: number;
  executing: number;
  succeeded: number;
  failed: number;
  loading?: boolean;
}) {
  const states = [
    { label: 'Pending', value: pending, description: 'Awaiting user review' },
    { label: 'User reviews', value: pending + approved, description: 'Plan, artifact, policy hash, and expiry visible' },
    { label: 'MFA confirmation', value: approved, description: 'MFA flag captured with approval decision' },
    { label: 'Approved', value: approved, description: 'Approval envelope accepted' },
    { label: 'Executing', value: executing, description: 'Safe simulated/no-op job status' },
    { label: 'Success / Failure', value: succeeded + failed, description: `${succeeded} succeeded, ${failed} failed or disabled` },
  ];
  return (
    <Card className="glass-card overflow-hidden">
      <div className="p-4 border-b border-white/5 bg-black/20 flex items-center gap-2">
        <Workflow className="h-4 w-4 text-blue-400" />
        <CardTitle className="text-neutral-100 text-base">End-to-end approval workflow</CardTitle>
      </div>
      <CardContent className="p-4">
        {loading ? (
          <TableSkeleton columns={6} rows={1} />
        ) : (
          <div className="grid gap-3 md:grid-cols-6">
            {states.map((state, index) => (
              <div key={state.label} className="rounded-md border border-white/10 bg-white/[0.02] p-3 min-h-[120px]">
                <div className="flex items-center justify-between gap-2">
                  <Badge variant="outline" className="bg-blue-500/10 text-blue-300 border-blue-500/20">{index + 1}</Badge>
                  <span className="text-xl font-semibold text-neutral-100">{state.value}</span>
                </div>
                <div className="mt-3 text-sm font-semibold text-neutral-100">{state.label}</div>
                <div className="mt-1 text-xs leading-5 text-neutral-400">{state.description}</div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function RecentPlans({ plans, loading }: { plans: RemediationPlan[]; loading?: boolean }) {
  return (
    <Card className="glass-card overflow-hidden">
      <div className="p-4 border-b border-white/5 bg-black/20 flex items-center justify-between">
        <CardTitle className="text-neutral-100 text-base flex items-center gap-2"><FileText className="w-4 h-4 text-blue-400" /> Recent plans</CardTitle>
        <Link className="text-xs text-blue-300 hover:text-blue-200" href="/remediation/plans">View all</Link>
      </div>
      <DataTable headers={['Risk', 'Summary', 'Status', 'Created']} loading={loading} emptyTitle="No remediation plans" emptyDescription="Generate a draft from findings, gaps, or recommendations.">
        {plans.map((plan) => (
          <tr key={plan.id} className="hover:bg-white/[0.02]">
            <td className="p-4"><LabelBadge value={plan.risk_level} tone={riskTone} /></td>
            <td className="p-4 text-neutral-100 max-w-md"><Link href={`/remediation/plans/${plan.id}`} className="hover:text-blue-300">{safeText(plan.summary)}</Link></td>
            <td className="p-4"><LabelBadge value={plan.status} /></td>
            <td className="p-4 text-neutral-400 text-xs">{dateText(plan.created_at)}</td>
          </tr>
        ))}
      </DataTable>
    </Card>
  );
}

function RecentApprovals({ approvals, loading }: { approvals: RemediationApproval[]; loading?: boolean }) {
  return (
    <Card className="glass-card overflow-hidden">
      <div className="p-4 border-b border-white/5 bg-black/20 flex items-center justify-between">
        <CardTitle className="text-neutral-100 text-base flex items-center gap-2"><LockKeyhole className="w-4 h-4 text-blue-400" /> Recent approvals</CardTitle>
        <Link className="text-xs text-blue-300 hover:text-blue-200" href="/remediation/approvals">View queue</Link>
      </div>
      <DataTable headers={['Status', 'Plan', 'Level', 'Expires']} loading={loading} emptyTitle="No approvals" emptyDescription="Validated plans can request HITL approval.">
        {approvals.map((approval) => (
          <tr key={approval.id} className="hover:bg-white/[0.02]">
            <td className="p-4"><LabelBadge value={approval.status} /></td>
            <td className="p-4 font-mono text-xs text-neutral-400">{safeText(approval.plan_id)}</td>
            <td className="p-4"><LabelBadge value={approval.required_approval_level || 'pending'} /></td>
            <td className="p-4 text-neutral-400 text-xs">{dateText(approval.expires_at)}</td>
          </tr>
        ))}
      </DataTable>
    </Card>
  );
}

function PlansView() {
  const { user } = useAuth();
  const canWrite = roleCanWrite(user);
  const [page, setPage] = useState(0);
  const [filters, setFilters] = useState({
    status: '',
    risk_level: '',
    provider: '',
    source_type: '',
    finding_id: '',
    gap_id: '',
    recommendation_id: '',
    created_by: '',
  });
  const [showGenerate, setShowGenerate] = useState(false);
  const [actionPlan, setActionPlan] = useState<RemediationPlan | null>(null);
  const [showRequest, setShowRequest] = useState(false);
  const query = useRemediationPlans({ ...filters, skip: page * PAGE_SIZE, limit: PAGE_SIZE });
  const validate = useValidateRemediationPlan();
  const plans = query.data?.items || [];
  const total = query.data?.total || 0;

  const setFilter = (key: keyof typeof filters, value: string) => {
    setPage(0);
    setFilters((current) => ({ ...current, [key]: value }));
  };

  const validatePlan = async (plan: RemediationPlan) => {
    try {
      await validate.mutateAsync(plan.id);
      toast.success('Validation completed');
    } catch (err: unknown) {
      toast.error(errorMessage(err));
    }
  };

  return (
    <ConsoleShell view="plans">
      {!canWrite && <div className="rounded-md border border-amber-500/20 bg-amber-500/10 px-4 py-3 text-sm text-amber-300">Your role can inspect remediation plans, but generation, validation, and approval requests are disabled.</div>}

      <Card className="glass-card">
        <CardContent className="p-4">
          <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3 flex-1">
              <FilterSelect label="Status" value={filters.status} onChange={(value) => setFilter('status', value)} options={[['', 'All statuses'], ['plan_drafted', 'Draft plan'], ['plan_validated', 'Validated'], ['approval_requested', 'Approval required'], ['approved', 'Approved'], ['rejected', 'Rejected'], ['expired', 'Expired']]} />
              <FilterSelect label="Risk level" value={filters.risk_level} onChange={(value) => setFilter('risk_level', value)} options={[['', 'All risk'], ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low']]} />
              <FilterSelect label="Provider" value={filters.provider} onChange={(value) => setFilter('provider', value)} options={[['', 'All providers'], ['aws', 'AWS'], ['github', 'GitHub'], ['gcp', 'GCP']]} />
              <FilterSelect label="Source type" value={filters.source_type} onChange={(value) => setFilter('source_type', value)} options={[['', 'All sources'], ['finding', 'Finding'], ['gap', 'Gap'], ['recommendation', 'Recommendation']]} />
              <Input aria-label="Finding ID" placeholder="finding_id" value={filters.finding_id} onChange={(event) => setFilter('finding_id', event.target.value)} className="bg-black/40 border-white/10 text-neutral-100 font-mono" />
              <Input aria-label="Gap ID" placeholder="gap_id" value={filters.gap_id} onChange={(event) => setFilter('gap_id', event.target.value)} className="bg-black/40 border-white/10 text-neutral-100 font-mono" />
              <Input aria-label="Recommendation ID" placeholder="recommendation_id" value={filters.recommendation_id} onChange={(event) => setFilter('recommendation_id', event.target.value)} className="bg-black/40 border-white/10 text-neutral-100 font-mono" />
              <Input aria-label="Created by" placeholder="created_by" value={filters.created_by} onChange={(event) => setFilter('created_by', event.target.value)} className="bg-black/40 border-white/10 text-neutral-100 font-mono" />
            </div>
            <div className="flex gap-2">
              <Button variant="outline" onClick={() => query.refetch()}><RefreshCw className="h-4 w-4 mr-1" /> Refresh</Button>
              <Button onClick={() => setShowGenerate(true)} disabled={!canWrite}>Generate draft</Button>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card className="glass-card overflow-hidden">
        <div className="p-4 border-b border-white/5 bg-black/20 flex items-center justify-between">
          <CardTitle className="text-neutral-100 text-base flex items-center gap-2"><Filter className="w-4 h-4 text-neutral-500" /> Remediation plans</CardTitle>
          <span className="text-xs text-neutral-500">{total} total</span>
        </div>
        <DataTable headers={['Summary', 'Provider', 'Risk', 'Status', 'Validation', 'Approval', 'Created', 'Actions']} loading={query.isLoading} emptyTitle="No plans found" emptyDescription="No remediation plans match the selected filters.">
          {plans.map((plan) => (
            <tr key={plan.id} className="hover:bg-white/[0.02]">
              <td className="p-4 text-neutral-100 min-w-[320px]"><Link href={`/remediation/plans/${plan.id}`} className="hover:text-blue-300">{safeText(plan.summary)}</Link></td>
              <td className="p-4 text-neutral-300 uppercase">{safeText(plan.provider || 'n/a')}</td>
              <td className="p-4"><LabelBadge value={plan.risk_level} tone={riskTone} /></td>
              <td className="p-4"><LabelBadge value={plan.status} /></td>
              <td className="p-4"><LabelBadge value={validationState(plan)} /></td>
              <td className="p-4"><LabelBadge value={approvalState(plan)} /></td>
              <td className="p-4 text-neutral-400 text-xs">{dateText(plan.created_at)}</td>
              <td className="p-4">
                <div className="flex flex-wrap gap-2">
                  <Link
                    href={`/remediation/plans/${plan.id}`}
                    className="inline-flex h-7 items-center justify-center rounded-md border border-white/10 bg-black/20 px-2.5 text-[0.8rem] font-medium text-neutral-200 hover:bg-white/[0.04]"
                  >
                    Detail
                  </Link>
                  <Button size="sm" variant="outline" disabled={!canWrite || validate.isPending || plan.status !== 'plan_drafted'} onClick={() => validatePlan(plan)}>Validate</Button>
                  <Button size="sm" variant="outline" disabled={!canWrite || plan.status !== 'plan_validated'} onClick={() => { setActionPlan(plan); setShowRequest(true); }}>Request approval</Button>
                </div>
              </td>
            </tr>
          ))}
        </DataTable>
        <div className="p-4 border-t border-white/5 flex items-center justify-between">
          <Button variant="outline" disabled={page === 0} onClick={() => setPage((current) => Math.max(0, current - 1))}>Previous</Button>
          <span className="text-xs text-neutral-500">Page {page + 1} of {Math.max(1, Math.ceil(total / PAGE_SIZE))}</span>
          <Button variant="outline" disabled={(page + 1) * PAGE_SIZE >= total} onClick={() => setPage((current) => current + 1)}>Next</Button>
        </div>
      </Card>

      <GeneratePlanDialog open={showGenerate} onOpenChange={setShowGenerate} />
      <ActionDialog kind="request" plan={actionPlan} open={showRequest} onOpenChange={setShowRequest} />
    </ConsoleShell>
  );
}

function PlanDetailView({ planId }: { planId?: string }) {
  const { user } = useAuth();
  const canWrite = roleCanWrite(user);
  const query = useRemediationPlan(planId);
  const validate = useValidateRemediationPlan();
  const [showRequest, setShowRequest] = useState(false);
  const plan = query.data;
  const check = latestPolicyCheck(plan);
  const approval = latestApproval(plan);

  const validatePlan = async () => {
    if (!plan) return;
    try {
      await validate.mutateAsync(plan.id);
      toast.success('Validation completed');
    } catch (err: unknown) {
      toast.error(errorMessage(err));
    }
  };

  return (
    <ConsoleShell view="plan-detail">
      {query.isLoading || !plan ? (
        <Card className="glass-card"><CardContent className="p-4"><TableSkeleton columns={2} rows={8} /></CardContent></Card>
      ) : (
        <>
          <div className="grid gap-4 lg:grid-cols-[1fr_360px]">
            <Card className="glass-card">
              <CardContent className="p-5 space-y-4">
                <div className="flex flex-wrap gap-2">
                  <LabelBadge value={plan.risk_level} tone={riskTone} />
                  <LabelBadge value={plan.status} />
                  <LabelBadge value={plan.provider || 'no provider'} />
                </div>
                <div>
                  <h3 className="text-xl font-semibold text-neutral-100">{safeText(plan.summary)}</h3>
                  <p className="mt-2 text-sm text-neutral-400 leading-6">{safeText(plan.expected_impact)}</p>
                </div>
                <div className="grid md:grid-cols-2 gap-3">
                  <Info label="Source reference" value={plan.finding_id || plan.gap_id || plan.recommendation_id || 'No source linked'} mono />
                  <Info label="Resource" value={plan.resource_ref || 'No resource reference'} mono />
                  <Info label="Created by" value={plan.created_by || 'System'} mono />
                  <Info label="Updated" value={dateText(plan.updated_at)} />
                </div>
              </CardContent>
            </Card>

            <Card className="glass-card">
              <CardContent className="p-5 space-y-3">
                <CardTitle className="text-neutral-100 text-base">Current review state</CardTitle>
                <Info label="Validation" value={check ? (check.passed ? 'passed' : 'failed') : 'Validation required'} />
                <Info label="Approval" value={approval ? approval.status : 'not requested'} />
                <Info label="Expiry" value={approval?.expires_at ? dateText(approval.expires_at) : 'No pending approval'} />
                <div className="flex flex-wrap gap-2 pt-2">
                  <Button variant="outline" disabled={!canWrite || validate.isPending || plan.status !== 'plan_drafted'} onClick={validatePlan}>Validate</Button>
                  <Button variant="outline" disabled={!canWrite || plan.status !== 'plan_validated'} onClick={() => setShowRequest(true)}>Request approval</Button>
                </div>
              </CardContent>
            </Card>
          </div>

          <ArtifactsPanel plan={plan} />
          <PolicyPanel check={check} />
          <RollbackPanel plan={plan} />
          <ApprovalSummary approval={approval} />
          <JobsSummary jobs={plan.execution_jobs} />
        </>
      )}
      <ActionDialog kind="request" plan={plan} open={showRequest} onOpenChange={setShowRequest} />
    </ConsoleShell>
  );
}

function ArtifactsPanel({ plan }: { plan: RemediationPlanDetail }) {
  return (
    <Card className="glass-card overflow-hidden">
      <div className="p-4 border-b border-white/5 bg-black/20">
        <CardTitle className="text-neutral-100 text-base flex items-center gap-2"><FileText className="h-4 w-4 text-blue-400" /> Artifacts</CardTitle>
      </div>
      <div className="p-4 space-y-4">
        <div className="rounded-md border border-blue-500/20 bg-blue-500/10 px-4 py-3 text-sm text-blue-200">Draft only. Not executable from UI.</div>
        {plan.artifacts.length === 0 ? (
          <EmptyState title="No artifacts" description="Draft generation creates redacted artifacts for review." icon={FileText} />
        ) : (
          plan.artifacts.map((artifact) => (
            <div key={artifact.id} className="rounded-md border border-white/10 bg-white/[0.02] p-4 space-y-3">
              <div className="flex flex-wrap gap-2">
                <LabelBadge value={artifact.artifact_type} />
                <LabelBadge value={artifact.status} />
                <Badge variant="outline" className="border-white/10 text-neutral-300">Non-executing artifact</Badge>
              </div>
              <Info label="Artifact hash" value={artifact.artifact_hash} mono />
              <Info label="Diff summary" value={artifact.diff_summary || 'No diff summary'} />
              <pre className="max-h-96 overflow-auto rounded-md border border-white/10 bg-black/50 p-3 text-xs text-neutral-300 whitespace-pre-wrap break-words">{safeText(artifact.content_redacted || '')}</pre>
              <Info label="Risk flags" value={JSON.stringify(artifact.risk_flags || {}, null, 2)} mono />
            </div>
          ))
        )}
      </div>
    </Card>
  );
}

function PolicyPanel({ check }: { check?: ReturnType<typeof latestPolicyCheck> }) {
  return (
    <Card className="glass-card">
      <CardContent className="p-5 space-y-4">
        <CardTitle className="text-neutral-100 text-base flex items-center gap-2"><ShieldCheck className="h-4 w-4 text-blue-400" /> Latest policy check</CardTitle>
        {!check ? (
          <div className="text-sm text-neutral-400">Validation required before approval can be requested.</div>
        ) : (
          <>
            <div className="flex flex-wrap gap-2">
              <Badge variant="outline" className={passTone(check.passed)}>{check.passed ? 'passed' : 'failed'}</Badge>
              <LabelBadge value={check.required_approval_level} />
            </div>
            <Info label="Policy check hash" value={check.policy_check_hash} mono />
            <FindingList title="Warnings" items={check.warnings} empty="No policy warnings returned." />
            <FindingList title="Blocking reasons" items={check.blocking_reasons} empty="No blocking reasons returned." />
          </>
        )}
      </CardContent>
    </Card>
  );
}

function FindingList({ title, items, empty }: { title: string; items: Array<Record<string, unknown>>; empty: string }) {
  return (
    <section>
      <h3 className="text-xs uppercase tracking-wider text-neutral-500 mb-2">{title}</h3>
      {items.length === 0 ? (
        <div className="rounded-md border border-white/10 bg-white/[0.02] p-3 text-xs text-neutral-500">{empty}</div>
      ) : (
        <div className="space-y-2">
          {items.map((item, index) => (
            <div key={index} className="rounded-md border border-white/10 bg-white/[0.02] p-3 text-sm text-neutral-300">
              <span className="font-mono text-xs text-neutral-500">{safeText(item.code || `item-${index + 1}`)}</span>
              <div className="mt-1">{safeText(item.message || JSON.stringify(item))}</div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function RollbackPanel({ plan }: { plan: RemediationPlanDetail }) {
  const rollback = plan.rollback_plan;
  return (
    <Card className="glass-card">
      <CardContent className="p-5 space-y-4">
        <CardTitle className="text-neutral-100 text-base flex items-center gap-2"><RotateCcw className="h-4 w-4 text-blue-400" /> Rollback plan</CardTitle>
        {!rollback ? (
          <div className="rounded-md border border-amber-500/20 bg-amber-500/10 px-4 py-3 text-sm text-amber-200">Rollback plan is missing and needs review before approval.</div>
        ) : (
          <>
            <div className="flex flex-wrap gap-2">
              <LabelBadge value={rollback.risk_level} tone={riskTone} />
              <Badge variant="outline" className="border-amber-500/20 text-amber-300">Manual review required</Badge>
            </div>
            <p className="text-sm text-neutral-300 leading-6 whitespace-pre-wrap">{safeText(rollback.rollback_summary)}</p>
            <Info label="Rollback artifact hash" value={rollback.rollback_artifact_hash || 'Not present'} mono />
          </>
        )}
      </CardContent>
    </Card>
  );
}

function ApprovalSummary({ approval }: { approval?: RemediationApproval }) {
  return (
    <Card className="glass-card">
      <CardContent className="p-5 space-y-4">
        <CardTitle className="text-neutral-100 text-base flex items-center gap-2"><LockKeyhole className="h-4 w-4 text-blue-400" /> Approval state</CardTitle>
        {!approval ? (
          <div className="text-sm text-neutral-400">No approval request has been created for this plan.</div>
        ) : (
          <div className="grid md:grid-cols-2 gap-3">
            <Info label="Status" value={approval.status} />
            <Info label="Required level" value={approval.required_approval_level || 'Not recorded'} />
            <Info label="Artifact hash" value={approval.artifact_hash} mono />
            <Info label="Policy hash" value={approval.policy_check_hash} mono />
            <Info label="Requested by" value={approval.requested_by || 'Unknown'} mono />
            <Info label="Expires" value={dateText(approval.expires_at)} />
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function JobsSummary({ jobs }: { jobs: RemediationExecutionJob[] }) {
  return (
    <Card className="glass-card">
      <CardContent className="p-5 space-y-4">
        <CardTitle className="text-neutral-100 text-base flex items-center gap-2"><Ban className="h-4 w-4 text-amber-400" /> Execution status</CardTitle>
        <div className="rounded-md border border-amber-500/20 bg-amber-500/10 px-4 py-3 text-sm text-amber-200">Only safe simulated/no-op records are visible. Real provider, Terraform, GitHub, and shell mutation remains blocked.</div>
        {jobs.length > 0 && (
          <div className="grid md:grid-cols-2 gap-3">
            {jobs.map((job) => <Info key={job.id} label={job.status} value={job.disabled_reason || job.dry_run_result_id || job.id} mono />)}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function ApprovalsView() {
  const { user } = useAuth();
  const canApprove = roleCanApprove(user);
  const canRevoke = roleCanRevoke(user);
  const [filters, setFilters] = useState({ status: '', required_approval_level: '', risk_level: '', expires_before: '', requested_by: '' });
  const [actionKind, setActionKind] = useState<ActionKind | null>(null);
  const [selectedApproval, setSelectedApproval] = useState<RemediationApproval | null>(null);
  const [detailApproval, setDetailApproval] = useState<RemediationApproval | null>(null);
  const approvalsQuery = useRemediationApprovals({
    status: filters.status,
    required_approval_level: filters.required_approval_level,
    expires_before: filters.expires_before,
    requested_by: filters.requested_by,
    skip: 0,
    limit: 100,
  });
  const plansQuery = useRemediationPlans({ skip: 0, limit: 200 });
  const planMap = useMemo(() => Object.fromEntries((plansQuery.data?.items || []).map((plan) => [plan.id, plan])), [plansQuery.data?.items]);
  const approvals = (approvalsQuery.data?.items || []).filter((approval) => !filters.risk_level || planMap[approval.plan_id]?.risk_level === filters.risk_level);

  const openAction = (kind: ActionKind, approval: RemediationApproval) => {
    setActionKind(kind);
    setSelectedApproval(approval);
  };

  return (
    <ConsoleShell view="approvals">
      {!canApprove && <div className="rounded-md border border-amber-500/20 bg-amber-500/10 px-4 py-3 text-sm text-amber-300">Your role can view approvals, but approval decisions are disabled.</div>}
      <Card className="glass-card">
        <CardContent className="p-4">
          <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
            <FilterSelect label="Status" value={filters.status} onChange={(value) => setFilters((current) => ({ ...current, status: value }))} options={[['', 'All statuses'], ['pending', 'Pending'], ['approved', 'Approved'], ['rejected', 'Rejected'], ['expired', 'Expired'], ['revoked', 'Revoked']]} />
            <FilterSelect label="Required level" value={filters.required_approval_level} onChange={(value) => setFilters((current) => ({ ...current, required_approval_level: value }))} options={[['', 'All levels'], ['operator', 'Operator'], ['admin', 'Admin'], ['owner', 'Owner'], ['security_admin', 'Security admin']]} />
            <FilterSelect label="Risk level" value={filters.risk_level} onChange={(value) => setFilters((current) => ({ ...current, risk_level: value }))} options={[['', 'All risk'], ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low']]} />
            <Input aria-label="Expires before" type="datetime-local" value={filters.expires_before} onChange={(event) => setFilters((current) => ({ ...current, expires_before: event.target.value }))} className="bg-black/40 border-white/10 text-neutral-100" />
            <Input aria-label="Requested by" placeholder="requested_by" value={filters.requested_by} onChange={(event) => setFilters((current) => ({ ...current, requested_by: event.target.value }))} className="bg-black/40 border-white/10 text-neutral-100 font-mono" />
          </div>
        </CardContent>
      </Card>

      <Card className="glass-card overflow-hidden">
        <div className="p-4 border-b border-white/5 bg-black/20 flex items-center justify-between">
          <CardTitle className="text-neutral-100 text-base flex items-center gap-2"><Clock className="w-4 h-4 text-blue-400" /> Approval queue</CardTitle>
          <span className="text-xs text-neutral-500">{approvals.length} shown</span>
        </div>
        <DataTable headers={['Status', 'Plan', 'Risk', 'Level', 'Hashes', 'Expires', 'Actions']} loading={approvalsQuery.isLoading || plansQuery.isLoading} emptyTitle="No approvals" emptyDescription="Validated plans appear here after approval is requested.">
          {approvals.map((approval) => {
            const plan = planMap[approval.plan_id];
            const isPending = approval.status === 'pending';
            return (
              <tr key={approval.id} className="hover:bg-white/[0.02]">
                <td className="p-4"><LabelBadge value={approval.status} /></td>
                <td className="p-4 text-neutral-100 min-w-[260px]">
                  <Link href={`/remediation/plans/${approval.plan_id}`} className="hover:text-blue-300">{safeText(plan?.summary || approval.plan_id)}</Link>
                </td>
                <td className="p-4"><LabelBadge value={plan?.risk_level || 'unknown'} tone={riskTone} /></td>
                <td className="p-4"><LabelBadge value={approval.required_approval_level || 'pending'} /></td>
                <td className="p-4 text-xs font-mono text-neutral-400 max-w-[260px]">
                  <div className="truncate">artifact {safeText(approval.artifact_hash)}</div>
                  <div className="truncate">policy {safeText(approval.policy_check_hash)}</div>
                </td>
                <td className="p-4 text-neutral-400 text-xs">{dateText(approval.expires_at)}</td>
                <td className="p-4">
                  <div className="flex flex-wrap gap-2">
                    <Button size="sm" variant="outline" onClick={() => setDetailApproval(approval)}>Detail</Button>
                    <Button size="sm" variant="outline" disabled={!canApprove || !isPending} onClick={() => openAction('approve', approval)}>Approve</Button>
                    <Button size="sm" variant="outline" disabled={!canApprove || !isPending} onClick={() => openAction('reject', approval)}>Reject</Button>
                    <Button size="sm" variant="outline" disabled={!canRevoke || !['pending', 'approved'].includes(String(approval.status))} onClick={() => openAction('revoke', approval)}>Revoke</Button>
                  </div>
                </td>
              </tr>
            );
          })}
        </DataTable>
      </Card>

      <ApprovalDetailSheet approval={detailApproval} plan={detailApproval ? planMap[detailApproval.plan_id] : undefined} onClose={() => setDetailApproval(null)} />
      <ActionDialog kind={actionKind} approval={selectedApproval} open={!!actionKind} onOpenChange={(open) => { if (!open) { setActionKind(null); setSelectedApproval(null); } }} />
    </ConsoleShell>
  );
}

function ApprovalDetailSheet({ approval, plan, onClose }: { approval: RemediationApproval | null; plan?: RemediationPlan; onClose: () => void }) {
  return (
    <Sheet open={!!approval} onOpenChange={(open) => !open && onClose()}>
      <SheetContent className="w-full sm:max-w-2xl bg-[#0a0a0a] border-white/10 text-neutral-100 overflow-y-auto">
        {approval && (
          <>
            <SheetHeader className="border-b border-white/5">
              <SheetTitle>Approval detail</SheetTitle>
              <SheetDescription className="font-mono text-xs">{approval.id}</SheetDescription>
            </SheetHeader>
            <div className="p-4 space-y-4">
              <div className="flex flex-wrap gap-2">
                <LabelBadge value={approval.status} />
                <LabelBadge value={approval.required_approval_level || 'pending'} />
                <LabelBadge value={plan?.risk_level || 'unknown'} tone={riskTone} />
              </div>
              <p className="text-sm text-neutral-300 leading-6">{safeText(plan?.summary || 'Plan summary unavailable in current page data.')}</p>
              <div className="grid md:grid-cols-2 gap-3">
                <Info label="Plan ID" value={approval.plan_id} mono />
                <Info label="Requested by" value={approval.requested_by || 'Unknown'} mono />
                <Info label="Artifact hash" value={approval.artifact_hash} mono />
                <Info label="Policy check hash" value={approval.policy_check_hash} mono />
                <Info label="Expiry" value={dateText(approval.expires_at)} />
                <Info label="MFA verified" value={approval.mfa_verified ? 'yes' : 'no'} />
              </div>
              <div className="rounded-md border border-white/10 bg-white/[0.02] p-3 text-xs text-neutral-500">Approval decisions do not execute changes. Expired, replay, and self-approval failures are returned safely by the backend.</div>
            </div>
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}

function JobsView() {
  const [filters, setFilters] = useState({ status: '', plan_id: '', approval_id: '' });
  const jobsQuery = useRemediationJobs({ ...filters, skip: 0, limit: 100 });
  const dryRunsQuery = useRemediationDryRuns({ skip: 0, limit: 100 });
  const verificationsQuery = useRemediationVerificationResults({ skip: 0, limit: 100 });
  const jobs = jobsQuery.data?.items || [];
  const dryRunMap = useMemo(
    () => Object.fromEntries((dryRunsQuery.data?.items || []).map((result) => [result.id, result] as const)),
    [dryRunsQuery.data?.items],
  );
  const verificationByJob = useMemo(
    () => Object.fromEntries((verificationsQuery.data?.items || []).filter((result) => result.job_id).map((result) => [result.job_id as string, result] as const)),
    [verificationsQuery.data?.items],
  );

  return (
    <ConsoleShell view="jobs">
      <Card className="glass-card">
        <CardContent className="p-4 space-y-4">
          <div className="rounded-md border border-amber-500/20 bg-amber-500/10 px-4 py-3 text-sm text-amber-200">Safe simulated/no-op execution records are visible for status and audit review. This UI still cannot start execute, apply, Terraform, provider, or shell mutation.</div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <FilterSelect label="Status" value={filters.status} onChange={(value) => setFilters((current) => ({ ...current, status: value }))} options={[['', 'All statuses'], ['disabled', 'Disabled'], ['dry_run_succeeded', 'Dry-run succeeded'], ['queued', 'Queued'], ['executing', 'Executing'], ['failed', 'Failed'], ['succeeded', 'Succeeded']]} />
            <Input aria-label="Plan ID" placeholder="plan_id" value={filters.plan_id} onChange={(event) => setFilters((current) => ({ ...current, plan_id: event.target.value }))} className="bg-black/40 border-white/10 text-neutral-100 font-mono" />
            <Input aria-label="Approval ID" placeholder="approval_id" value={filters.approval_id} onChange={(event) => setFilters((current) => ({ ...current, approval_id: event.target.value }))} className="bg-black/40 border-white/10 text-neutral-100 font-mono" />
          </div>
        </CardContent>
      </Card>

      <Card className="glass-card overflow-hidden">
        <div className="p-4 border-b border-white/5 bg-black/20">
          <CardTitle className="text-neutral-100 text-base flex items-center gap-2"><Ban className="h-4 w-4 text-amber-400" /> Execution jobs</CardTitle>
        </div>
        <DataTable headers={['Status', 'Plan', 'Approval', 'Dry-run', 'Verification', 'Reason', 'Created']} loading={jobsQuery.isLoading || dryRunsQuery.isLoading || verificationsQuery.isLoading} emptyTitle="No execution jobs" emptyDescription="Safe controlled execution records appear here after approval and dry-run.">
          {jobs.map((job) => {
            const dryRun = job.dry_run_result_id ? dryRunMap[job.dry_run_result_id] : undefined;
            const verification = verificationByJob[job.id];
            return (
              <tr key={job.id} className="hover:bg-white/[0.02]">
                <td className="p-4"><LabelBadge value={job.status} /></td>
                <td className="p-4 font-mono text-xs text-neutral-400">{safeText(job.plan_id)}</td>
                <td className="p-4 font-mono text-xs text-neutral-400">{safeText(job.approval_id || '-')}</td>
                <td className="p-4 text-neutral-300 max-w-xs"><DryRunCell dryRun={dryRun} /></td>
                <td className="p-4 text-neutral-300 max-w-sm"><VerificationCell verification={verification} /></td>
                <td className="p-4 text-neutral-300 max-w-lg">{safeText(job.disabled_reason || 'Controlled safe record only. No external mutation was attempted.')}</td>
                <td className="p-4 text-neutral-400 text-xs">{dateText(job.created_at)}</td>
              </tr>
            );
          })}
        </DataTable>
      </Card>
    </ConsoleShell>
  );
}

function DryRunCell({ dryRun }: { dryRun?: RemediationDryRunResult }) {
  if (!dryRun) return <span className="text-neutral-500">No dry-run linked</span>;
  return (
    <div className="space-y-1">
      <LabelBadge value={dryRun.status} />
      <div className="text-xs text-neutral-400">{safeText(dryRun.dry_run_type)}</div>
      <div className="text-xs text-neutral-500">{safeText(dryRun.output_summary)}</div>
    </div>
  );
}

function VerificationCell({ verification }: { verification?: RemediationVerificationResult }) {
  if (!verification) return <span className="text-neutral-500">No verification result</span>;
  return (
    <div className="space-y-1">
      <LabelBadge value={verification.status} />
      <div className="text-xs text-neutral-400">{verification.verified ? 'verified' : 'not verified'}</div>
      <div className="text-xs text-neutral-500">{safeText(verification.verification_summary)}</div>
    </div>
  );
}

export function RemediationConsole({
  view = 'overview',
  planId,
}: {
  view?: RemediationView;
  planId?: string;
}) {
  if (view === 'plans') return <PlansView />;
  if (view === 'plan-detail') return <PlanDetailView planId={planId} />;
  if (view === 'approvals') return <ApprovalsView />;
  if (view === 'jobs') return <JobsView />;
  return <Overview />;
}
