"use client";

import Link from 'next/link';
import { useMemo, useState } from 'react';
import {
  AlertTriangle,
  BookOpen,
  Bot,
  CheckCircle2,
  Database,
  FileText,
  Filter,
  Layers,
  Library,
  MessageSquare,
  RefreshCw,
  ShieldCheck,
} from 'lucide-react';
import { toast } from 'sonner';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import { EmptyState } from '@/components/shared/states';
import { TableSkeleton } from '@/components/shared/loaders';
import { useAuth } from '@/hooks/use-auth';
import {
  ComplianceAssessment,
  ComplianceGap,
  ComplianceMapping,
  EvidenceItem,
  KnowledgeDocument,
  useAskCompliance,
  useComplianceAskSessions,
  useComplianceAssessments,
  useComplianceControl,
  useComplianceControls,
  useComplianceEvidence,
  useComplianceFramework,
  useComplianceFrameworks,
  useComplianceGaps,
  useComplianceMappings,
  useComplianceRecommendations,
  useIngestKnowledge,
  useKnowledgeDocuments,
  useReviewComplianceMapping,
  useRunComplianceAssessment,
} from '@/hooks/use-data';

type ConsoleView =
  | 'overview'
  | 'frameworks'
  | 'framework-detail'
  | 'control-detail'
  | 'evidence'
  | 'gaps'
  | 'recommendations'
  | 'knowledge'
  | 'assistant';

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

const navItems: Array<{ view: ConsoleView; label: string; href: string; icon: typeof ShieldCheck }> = [
  { view: 'overview', label: 'Overview', href: '/compliance', icon: ShieldCheck },
  { view: 'frameworks', label: 'Frameworks', href: '/compliance/frameworks', icon: Layers },
  { view: 'evidence', label: 'Evidence', href: '/compliance/evidence', icon: Database },
  { view: 'gaps', label: 'Gaps', href: '/compliance/gaps', icon: AlertTriangle },
  { view: 'recommendations', label: 'Recommendations', href: '/compliance/recommendations', icon: CheckCircle2 },
  { view: 'knowledge', label: 'Knowledge', href: '/compliance/knowledge', icon: Library },
  { view: 'assistant', label: 'Assistant', href: '/compliance/assistant', icon: Bot },
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

function pct(value?: number) {
  return `${Math.round(value ?? 0)}%`;
}

function dateText(value?: string | null) {
  if (!value) return 'Not recorded';
  return new Date(value).toLocaleString();
}

function bandTone(value: string) {
  switch (value) {
    case 'strong':
      return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
    case 'mostly_supported':
      return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
    case 'at_risk':
      return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
    case 'high_risk':
    case 'critical':
    case 'high':
      return 'bg-red-500/10 text-red-400 border-red-500/20';
    case 'medium':
      return 'bg-orange-500/10 text-orange-400 border-orange-500/20';
    case 'low':
      return 'bg-sky-500/10 text-sky-400 border-sky-500/20';
    default:
      return 'bg-white/5 text-neutral-300 border-white/10';
  }
}

function statusTone(value: string) {
  switch (value) {
    case 'active':
    case 'approved':
    case 'auto_approved':
      return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
    case 'needs_review':
    case 'review_recommended':
    case 'stale':
    case 'expired':
      return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
    case 'rejected':
    case 'overridden':
      return 'bg-violet-500/10 text-violet-400 border-violet-500/20';
    default:
      return 'bg-white/5 text-neutral-300 border-white/10';
  }
}

function LabelBadge({ value, tone = statusTone }: { value?: string | null; tone?: (value: string) => string }) {
  const text = safeText(value || 'unknown').replaceAll('_', ' ');
  return <Badge variant="outline" className={tone(value || 'unknown')}>{text}</Badge>;
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
        {options.map(([optionValue, labelText]) => (
          <option key={optionValue} value={optionValue}>{labelText}</option>
        ))}
      </select>
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

function ConsoleShell({
  view,
  children,
}: {
  view: ConsoleView;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-6 max-w-[1600px] mx-auto pb-10">
      <div className="flex flex-col xl:flex-row items-start xl:items-end justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-neutral-100">Compliance Console</h2>
          <p className="text-sm text-neutral-400 mt-1">Evidence-supported posture across frameworks, controls, findings, evidence, and knowledge sources.</p>
        </div>
        <div className="flex flex-wrap gap-2">
          {navItems.map((item) => {
            const Icon = item.icon;
            const active = view === item.view || (view === 'framework-detail' && item.view === 'frameworks') || (view === 'control-detail' && item.view === 'frameworks');
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
        Not legal advice. This console describes evidence-supported posture and review status only.
      </div>

      {children}
    </div>
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

function Overview({ canRunAssessment }: { canRunAssessment: boolean }) {
  const frameworksQuery = useComplianceFrameworks({ status: 'active', limit: 100 });
  const assessmentsQuery = useComplianceAssessments({ latest_only: true, limit: 20 });
  const gapsQuery = useComplianceGaps({ limit: 5 });
  const staleEvidenceQuery = useComplianceEvidence({ stale: true, limit: 1 });
  const reviewMappingsQuery = useComplianceMappings({ review_status: 'needs_review', limit: 1 });
  const runAssessment = useRunComplianceAssessment();
  const frameworks = frameworksQuery.data || [];
  const assessments = useMemo(() => assessmentsQuery.data?.items || [], [assessmentsQuery.data?.items]);
  const latestByFramework = useMemo(() => Object.fromEntries(assessments.map((item) => [item.framework_id, item])), [assessments]);

  const runFirstAssessment = async () => {
    const framework = frameworks[0];
    if (!framework) return;
    try {
      await runAssessment.mutateAsync({ framework_id: framework.id });
      toast.success('Assessment run completed');
    } catch (err: unknown) {
      toast.error(errorMessage(err));
    }
  };

  return (
    <ConsoleShell view="overview">
      <div className="grid gap-4 md:grid-cols-4">
        <Metric label="Frameworks" value={frameworks.length} hint="Active catalog entries" />
        <Metric label="Assessments" value={assessments.length} hint="Latest framework runs" />
        <Metric label="Top gaps" value={gapsQuery.data?.total ?? 0} hint="Detected review items" />
        <Metric label="Needs review" value={reviewMappingsQuery.data?.total ?? 0} hint="Mapping decisions queued" />
      </div>

      <Card className="glass-card overflow-hidden">
        <div className="p-4 border-b border-white/5 bg-black/20 flex flex-col md:flex-row md:items-center justify-between gap-3">
          <CardTitle className="text-neutral-100 text-base flex items-center gap-2"><ShieldCheck className="w-4 h-4 text-blue-400" /> Framework posture</CardTitle>
          <div className="flex items-center gap-2">
            <Badge variant="outline" className="border-amber-500/20 text-amber-300">{staleEvidenceQuery.data?.total ?? 0} stale evidence</Badge>
            <Button variant="outline" disabled={!canRunAssessment || runAssessment.isPending || frameworks.length === 0} onClick={runFirstAssessment}>
              <RefreshCw className="h-4 w-4 mr-2" />
              {runAssessment.isPending ? 'Running' : 'Run assessment'}
            </Button>
          </div>
        </div>
        <DataTable headers={['Framework', 'Version', 'Controls', 'Score band', 'Score', 'Last run', 'Actions']} loading={frameworksQuery.isLoading || assessmentsQuery.isLoading} emptyTitle="No frameworks seeded" emptyDescription="Seed the compliance catalog before reviewing posture.">
          {frameworks.map((framework) => {
            const assessment = latestByFramework[framework.id] as ComplianceAssessment | undefined;
            return (
              <tr key={framework.id} className="hover:bg-white/[0.02]">
                <td className="p-4 text-neutral-100 font-medium">{safeText(framework.name)}</td>
                <td className="p-4 text-neutral-400">{safeText(framework.version)}</td>
                <td className="p-4 text-neutral-300">{framework.control_count}</td>
                <td className="p-4">{assessment ? <LabelBadge value={assessment.score_band} tone={bandTone} /> : <span className="text-neutral-500">No assessment yet</span>}</td>
                <td className="p-4 text-neutral-300">{assessment ? pct(assessment.score) : '-'}</td>
                <td className="p-4 text-neutral-400">{assessment ? dateText(assessment.started_at) : '-'}</td>
                <td className="p-4"><Link className="text-blue-300 hover:text-blue-200" href={`/compliance/frameworks/${framework.id}`}>Open</Link></td>
              </tr>
            );
          })}
        </DataTable>
      </Card>

      <Card className="glass-card overflow-hidden">
        <div className="p-4 border-b border-white/5 bg-black/20">
          <CardTitle className="text-neutral-100 text-base flex items-center gap-2"><AlertTriangle className="w-4 h-4 text-amber-400" /> Top gaps</CardTitle>
        </div>
        <DataTable headers={['Severity', 'Control', 'Type', 'Evidence', 'Reason']} loading={gapsQuery.isLoading} emptyTitle="No gaps detected" emptyDescription="Run an assessment to populate evidence-backed gap analysis.">
          {(gapsQuery.data?.items || []).map((gap) => (
            <tr key={gap.id} className="hover:bg-white/[0.02]">
              <td className="p-4"><LabelBadge value={gap.severity} tone={bandTone} /></td>
              <td className="p-4 text-neutral-300">{safeText(gap.control_code || gap.control_id)}</td>
              <td className="p-4"><LabelBadge value={gap.gap_type} /></td>
              <td className="p-4 text-neutral-400">{safeText(gap.evidence_status)}</td>
              <td className="p-4 text-neutral-300">{safeText(gap.reason)}</td>
            </tr>
          ))}
        </DataTable>
      </Card>
    </ConsoleShell>
  );
}

function FrameworksView({ frameworkId }: { frameworkId?: string }) {
  const [filters, setFilters] = useState({ domain: '', requires_review: '', search: '' });
  const frameworksQuery = useComplianceFrameworks({ status: 'active', limit: 100 });
  const frameworkQuery = useComplianceFramework(frameworkId);
  const selectedFramework = frameworkQuery.data || frameworksQuery.data?.[0] || null;
  const controlsQuery = useComplianceControls(frameworkId || selectedFramework?.id, {
    domain: filters.domain,
    requires_review: filters.requires_review,
    search: filters.search,
    limit: 200,
  });
  const controls = controlsQuery.data?.items || [];
  const domains = Array.from(new Set(controls.map((control) => control.domain).filter(Boolean)));

  if (!frameworkId) {
    return (
      <ConsoleShell view="frameworks">
        <Card className="glass-card overflow-hidden">
          <div className="p-4 border-b border-white/5 bg-black/20">
            <CardTitle className="text-neutral-100 text-base flex items-center gap-2"><Layers className="w-4 h-4 text-blue-400" /> Framework catalog</CardTitle>
          </div>
          <DataTable headers={['Framework', 'Version', 'Controls', 'Status', 'License', 'Actions']} loading={frameworksQuery.isLoading} emptyTitle="No frameworks seeded" emptyDescription="The global catalog has not been seeded yet.">
            {(frameworksQuery.data || []).map((framework) => (
              <tr key={framework.id} className="hover:bg-white/[0.02]">
                <td className="p-4 text-neutral-100 font-medium">{safeText(framework.name)}</td>
                <td className="p-4 text-neutral-400">{safeText(framework.version)}</td>
                <td className="p-4 text-neutral-300">{framework.control_count}</td>
                <td className="p-4"><LabelBadge value={framework.status} /></td>
                <td className="p-4 text-neutral-400 max-w-md">{safeText(framework.license_note)}</td>
                <td className="p-4"><Link className="text-blue-300 hover:text-blue-200" href={`/compliance/frameworks/${framework.id}`}>View controls</Link></td>
              </tr>
            ))}
          </DataTable>
        </Card>
      </ConsoleShell>
    );
  }

  return (
    <ConsoleShell view="framework-detail">
      <div className="grid gap-4 lg:grid-cols-[1fr_320px]">
        <Card className="glass-card">
          <CardContent className="p-5">
            <div className="flex flex-wrap items-center gap-2 mb-3">
              <LabelBadge value={selectedFramework?.key} />
              <LabelBadge value={selectedFramework?.status} />
              <span className="text-xs text-neutral-500">{safeText(selectedFramework?.version)}</span>
            </div>
            <h3 className="text-xl font-semibold text-neutral-100">{safeText(selectedFramework?.name || 'Framework')}</h3>
            <p className="mt-2 text-sm text-neutral-400 leading-6">{safeText(selectedFramework?.description || 'No framework description available.')}</p>
          </CardContent>
        </Card>
        <Card className="glass-card">
          <CardContent className="p-5">
            <div className="text-xs uppercase tracking-wider text-neutral-500">Catalog metadata</div>
            <div className="mt-3 space-y-2 text-sm text-neutral-300">
              <div>{selectedFramework?.control_count ?? controls.length} controls</div>
              <div>{safeText(selectedFramework?.license_note)}</div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card className="glass-card">
        <CardContent className="p-4">
          <div className="flex items-center gap-2 mb-4"><Filter className="w-4 h-4 text-neutral-500" /><CardTitle className="text-neutral-100 text-base">Control filters</CardTitle></div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <FilterSelect label="Domain" value={filters.domain} onChange={(value) => setFilters((current) => ({ ...current, domain: value }))} options={[['', 'All domains'], ...domains.map((domain) => [domain, domain] as [string, string])]} />
            <FilterSelect label="Requires review" value={filters.requires_review} onChange={(value) => setFilters((current) => ({ ...current, requires_review: value }))} options={[['', 'Any'], ['true', 'Requires review'], ['false', 'No review flag']]} />
            <div className="space-y-1">
              <label className="text-[10px] uppercase tracking-wider text-neutral-500">Search</label>
              <Input aria-label="Search controls" value={filters.search} onChange={(event) => setFilters((current) => ({ ...current, search: event.target.value }))} placeholder="Control code, title, summary" />
            </div>
          </div>
        </CardContent>
      </Card>

      <Card className="glass-card overflow-hidden">
        <div className="p-4 border-b border-white/5 bg-black/20"><CardTitle className="text-neutral-100 text-base">Controls</CardTitle></div>
        <DataTable headers={['Code', 'Title', 'Domain', 'Category', 'Review', 'Requirements', 'Actions']} loading={controlsQuery.isLoading} emptyTitle="No controls found" emptyDescription="No controls match the selected filters.">
          {controls.map((control) => (
            <tr key={control.id} className="hover:bg-white/[0.02]">
              <td className="p-4 font-mono text-xs text-neutral-300">{safeText(control.control_code)}</td>
              <td className="p-4 text-neutral-100">{safeText(control.title)}</td>
              <td className="p-4 text-neutral-400">{safeText(control.domain)}</td>
              <td className="p-4 text-neutral-400">{safeText(control.category || '-')}</td>
              <td className="p-4">{control.requires_review ? <LabelBadge value="needs_review" /> : <span className="text-neutral-500">Standard</span>}</td>
              <td className="p-4 text-neutral-300">{control.requirements.length}</td>
              <td className="p-4"><Link className="text-blue-300 hover:text-blue-200" href={`/compliance/controls/${control.id}`}>Open</Link></td>
            </tr>
          ))}
        </DataTable>
      </Card>
    </ConsoleShell>
  );
}

function MappingReviewPanel({ mapping, canReview }: { mapping: ComplianceMapping; canReview: boolean }) {
  const [reason, setReason] = useState('');
  const review = useReviewComplianceMapping();

  const submit = async (review_status: 'approved' | 'rejected' | 'overridden') => {
    try {
      await review.mutateAsync({ id: mapping.id, data: { review_status, override_reason: reason || undefined } });
      toast.success('Mapping review saved');
      setReason('');
    } catch (err: unknown) {
      toast.error(errorMessage(err));
    }
  };

  if (!canReview) return <span className="text-xs text-neutral-500">Review actions hidden for this role.</span>;

  return (
    <div className="flex flex-col gap-2 min-w-[280px]">
      <Input aria-label={`Override reason ${mapping.id}`} value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Override reason when needed" />
      <div className="flex flex-wrap gap-2">
        <Button variant="outline" size="sm" disabled={review.isPending} onClick={() => submit('approved')}>Approve</Button>
        <Button variant="outline" size="sm" disabled={review.isPending} onClick={() => submit('rejected')}>Reject</Button>
        <Button variant="outline" size="sm" disabled={review.isPending || !reason.trim()} onClick={() => submit('overridden')}>Override</Button>
      </div>
    </div>
  );
}

function ControlDetailView({ controlId, canReview }: { controlId?: string; canReview: boolean }) {
  const controlQuery = useComplianceControl(controlId);
  const control = controlQuery.data;
  const mappingsQuery = useComplianceMappings({ control_id: controlId, limit: 100 });
  const evidenceQuery = useComplianceEvidence({ control_id: controlId, limit: 100 });
  const gapsQuery = useComplianceGaps({ control_id: controlId, limit: 100 });
  const recsQuery = useComplianceRecommendations({ control_id: controlId, limit: 25 });
  const assessmentsQuery = useComplianceAssessments({ latest_only: true, limit: 100 });
  const controlResult = assessmentsQuery.data?.items.flatMap((assessment) => assessment.control_results || []).find((result) => result.control_id === controlId);

  return (
    <ConsoleShell view="control-detail">
      <Card className="glass-card">
        <CardContent className="p-5">
          <div className="flex flex-wrap gap-2 mb-3">
            <LabelBadge value={control?.domain} />
            {control?.requires_review && <LabelBadge value="needs_review" />}
            {controlResult && <LabelBadge value={controlResult.score_band} tone={bandTone} />}
          </div>
          <h3 className="text-xl font-semibold text-neutral-100">{safeText(control?.control_code)} · {safeText(control?.title || 'Control')}</h3>
          <p className="mt-2 text-sm text-neutral-400 leading-6">{safeText(control?.summary || 'Control details are loading.')}</p>
          {controlResult && <p className="mt-3 text-sm text-neutral-300">Score {pct(controlResult.score)}: {safeText(controlResult.explanation)}</p>}
        </CardContent>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="glass-card overflow-hidden">
          <div className="p-4 border-b border-white/5 bg-black/20"><CardTitle className="text-neutral-100 text-base">Requirements</CardTitle></div>
          <div className="divide-y divide-white/5">
            {(control?.requirements || []).map((requirement) => (
              <div key={requirement.id} className="p-4">
                <div className="font-mono text-xs text-neutral-500">{safeText(requirement.requirement_key)}</div>
                <div className="mt-1 text-sm text-neutral-200">{safeText(requirement.summary)}</div>
                {requirement.evidence_expectation && <div className="mt-2 text-xs text-neutral-500">{safeText(requirement.evidence_expectation)}</div>}
              </div>
            ))}
          </div>
        </Card>

        <Card className="glass-card overflow-hidden">
          <div className="p-4 border-b border-white/5 bg-black/20"><CardTitle className="text-neutral-100 text-base">Recommendation summary</CardTitle></div>
          <div className="divide-y divide-white/5">
            {(recsQuery.data?.items || []).map((rec) => (
              <div key={rec.id} className="p-4">
                <div className="flex gap-2 mb-2"><LabelBadge value={rec.severity} tone={bandTone} /><LabelBadge value={rec.status} /></div>
                <div className="text-sm text-neutral-200">{safeText(rec.title)}</div>
                <div className="text-xs text-neutral-500 mt-1">{safeText(rec.summary)}</div>
              </div>
            ))}
            {(recsQuery.data?.items || []).length === 0 && <div className="p-4 text-sm text-neutral-500">No deterministic recommendations for this control yet.</div>}
          </div>
        </Card>
      </div>

      <Card className="glass-card overflow-hidden">
        <div className="p-4 border-b border-white/5 bg-black/20"><CardTitle className="text-neutral-100 text-base">Mapped findings</CardTitle></div>
        <DataTable headers={['Confidence', 'Status', 'Rule', 'Finding', 'Source', 'Review']} loading={mappingsQuery.isLoading} emptyTitle="No mappings" emptyDescription="No findings are mapped to this control yet.">
          {(mappingsQuery.data?.items || []).map((mapping) => (
            <tr key={mapping.id} className="hover:bg-white/[0.02] align-top">
              <td className="p-4 text-neutral-300">{pct(mapping.confidence * 100)}</td>
              <td className="p-4"><LabelBadge value={mapping.review_status} /></td>
              <td className="p-4 font-mono text-xs text-neutral-400">{safeText(mapping.rule_id)}</td>
              <td className="p-4 font-mono text-xs text-neutral-400">{safeText(mapping.finding_id)}</td>
              <td className="p-4 text-neutral-400">{safeText(mapping.mapping_source)}</td>
              <td className="p-4"><MappingReviewPanel mapping={mapping} canReview={canReview} /></td>
            </tr>
          ))}
        </DataTable>
      </Card>

      <EvidenceTable title="Evidence items" items={evidenceQuery.data?.items || []} loading={evidenceQuery.isLoading} />
      <GapsTable items={gapsQuery.data?.items || []} loading={gapsQuery.isLoading} />
    </ConsoleShell>
  );
}

function EvidenceTable({ title, items, loading }: { title: string; items: EvidenceItem[]; loading?: boolean }) {
  const [selected, setSelected] = useState<EvidenceItem | null>(null);
  return (
    <>
      <Card className="glass-card overflow-hidden">
        <div className="p-4 border-b border-white/5 bg-black/20"><CardTitle className="text-neutral-100 text-base">{title}</CardTitle></div>
        <DataTable headers={['Status', 'Source', 'Control', 'Summary', 'Freshness', 'Proof', 'Detail']} loading={loading} emptyTitle="No evidence" emptyDescription="Evidence appears after mappings and assessment runs produce safe summaries.">
          {items.map((item) => (
            <tr key={item.id} className="hover:bg-white/[0.02]">
              <td className="p-4"><LabelBadge value={item.status} /></td>
              <td className="p-4 text-neutral-400">{safeText(item.source_type)}</td>
              <td className="p-4 text-neutral-300">{safeText(item.control_code || item.control_id)}</td>
              <td className="p-4 text-neutral-300 max-w-xl">{safeText(item.safe_summary)}</td>
              <td className="p-4 text-neutral-400">{dateText(item.freshness_expires_at)}</td>
              <td className="p-4 font-mono text-xs text-neutral-500">{safeText(item.proof_hash || '-')}</td>
              <td className="p-4"><Button variant="outline" size="sm" onClick={() => setSelected(item)}>Detail</Button></td>
            </tr>
          ))}
        </DataTable>
      </Card>
      <Sheet open={!!selected} onOpenChange={(open) => !open && setSelected(null)}>
        <SheetContent className="w-full sm:max-w-2xl bg-[#0a0a0a] border-white/10 text-neutral-100 overflow-y-auto">
          {selected && (
            <>
              <SheetHeader className="border-b border-white/5">
                <SheetTitle>Evidence detail</SheetTitle>
                <SheetDescription className="font-mono text-xs">{selected.id}</SheetDescription>
              </SheetHeader>
              <div className="p-4 space-y-4 text-sm">
                <p className="text-neutral-300 leading-6">{safeText(selected.safe_summary)}</p>
                <Info label="Control" value={selected.control_code || selected.control_id} mono />
                <Info label="Finding" value={selected.finding_id || 'Not linked'} mono />
                <Info label="Assessment proof" value={selected.proof_hash || 'Not present'} mono />
                <Info label="Freshness expiration" value={dateText(selected.freshness_expires_at)} />
                <div className="rounded-md border border-white/10 bg-white/[0.02] p-3 text-xs text-neutral-500">Raw provider payloads and secrets are not displayed.</div>
              </div>
            </>
          )}
        </SheetContent>
      </Sheet>
    </>
  );
}

function EvidenceView() {
  const frameworksQuery = useComplianceFrameworks({ status: 'active', limit: 100 });
  const [filters, setFilters] = useState({ framework_id: '', control_id: '', source_type: '', status: '', stale: '' });
  const evidenceQuery = useComplianceEvidence({ ...filters, stale: filters.stale || undefined, limit: PAGE_SIZE });
  return (
    <ConsoleShell view="evidence">
      <Card className="glass-card">
        <CardContent className="p-4">
          <div className="flex items-center gap-2 mb-4"><Filter className="w-4 h-4 text-neutral-500" /><CardTitle className="text-neutral-100 text-base">Evidence filters</CardTitle></div>
          <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
            <FilterSelect label="Framework" value={filters.framework_id} onChange={(value) => setFilters((current) => ({ ...current, framework_id: value }))} options={[['', 'All frameworks'], ...(frameworksQuery.data || []).map((fw) => [fw.id, fw.key.toUpperCase()] as [string, string])]} />
            <div className="space-y-1"><label className="text-[10px] uppercase tracking-wider text-neutral-500">Control ID</label><Input aria-label="Control" value={filters.control_id} onChange={(event) => setFilters((current) => ({ ...current, control_id: event.target.value }))} /></div>
            <FilterSelect label="Source type" value={filters.source_type} onChange={(value) => setFilters((current) => ({ ...current, source_type: value }))} options={[['', 'All sources'], ['finding_mapping', 'Finding mapping'], ['audit_log', 'Audit log'], ['manual', 'Manual'], ['system', 'System']]} />
            <FilterSelect label="Status" value={filters.status} onChange={(value) => setFilters((current) => ({ ...current, status: value }))} options={[['', 'All statuses'], ['active', 'Active'], ['resolved', 'Resolved'], ['suppressed', 'Suppressed'], ['stale', 'Stale'], ['expired', 'Expired']]} />
            <FilterSelect label="Freshness" value={filters.stale} onChange={(value) => setFilters((current) => ({ ...current, stale: value }))} options={[['', 'Any'], ['true', 'Stale or expired'], ['false', 'Fresh']]} />
          </div>
        </CardContent>
      </Card>
      <EvidenceTable title="Evidence library" items={evidenceQuery.data?.items || []} loading={evidenceQuery.isLoading} />
    </ConsoleShell>
  );
}

function GapsTable({ items, loading }: { items: ComplianceGap[]; loading?: boolean }) {
  return (
    <Card className="glass-card overflow-hidden">
      <div className="p-4 border-b border-white/5 bg-black/20"><CardTitle className="text-neutral-100 text-base">Gaps</CardTitle></div>
      <DataTable headers={['Severity', 'Type', 'Control', 'Evidence', 'Reason', 'Links']} loading={loading} emptyTitle="No gaps" emptyDescription="No matching gaps were returned by the API.">
        {items.map((gap) => (
          <tr key={gap.id} className="hover:bg-white/[0.02]">
            <td className="p-4"><LabelBadge value={gap.severity} tone={bandTone} /></td>
            <td className="p-4"><LabelBadge value={gap.gap_type} /></td>
            <td className="p-4 text-neutral-300">{safeText(gap.control_code || gap.control_id)}</td>
            <td className="p-4 text-neutral-400">{safeText(gap.evidence_status)}</td>
            <td className="p-4 text-neutral-300 max-w-xl">{safeText(gap.reason)}</td>
            <td className="p-4 text-xs text-neutral-500">{gap.evidence_id ? `Evidence ${gap.evidence_id}` : 'Evidence not linked'}</td>
          </tr>
        ))}
      </DataTable>
    </Card>
  );
}

function GapsView() {
  const frameworksQuery = useComplianceFrameworks({ status: 'active', limit: 100 });
  const [filters, setFilters] = useState({ framework_id: '', control_id: '', severity: '', gap_type: '', evidence_status: '' });
  const gapsQuery = useComplianceGaps({ ...filters, limit: PAGE_SIZE });
  return (
    <ConsoleShell view="gaps">
      <Card className="glass-card">
        <CardContent className="p-4">
          <div className="flex items-center gap-2 mb-4"><Filter className="w-4 h-4 text-neutral-500" /><CardTitle className="text-neutral-100 text-base">Gap filters</CardTitle></div>
          <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
            <FilterSelect label="Framework" value={filters.framework_id} onChange={(value) => setFilters((current) => ({ ...current, framework_id: value }))} options={[['', 'All frameworks'], ...(frameworksQuery.data || []).map((fw) => [fw.id, fw.key.toUpperCase()] as [string, string])]} />
            <div className="space-y-1"><label className="text-[10px] uppercase tracking-wider text-neutral-500">Control ID</label><Input aria-label="Control" value={filters.control_id} onChange={(event) => setFilters((current) => ({ ...current, control_id: event.target.value }))} /></div>
            <FilterSelect label="Severity" value={filters.severity} onChange={(value) => setFilters((current) => ({ ...current, severity: value }))} options={[['', 'All severities'], ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low']]} />
            <FilterSelect label="Gap type" value={filters.gap_type} onChange={(value) => setFilters((current) => ({ ...current, gap_type: value }))} options={[['', 'All types'], ['missing_evidence', 'Missing evidence'], ['stale_evidence', 'Stale evidence'], ['unresolved_finding', 'Unresolved finding'], ['needs_review', 'Needs review']]} />
            <FilterSelect label="Evidence status" value={filters.evidence_status} onChange={(value) => setFilters((current) => ({ ...current, evidence_status: value }))} options={[['', 'Any'], ['active', 'Active'], ['expired', 'Expired'], ['missing', 'Missing']]} />
          </div>
        </CardContent>
      </Card>
      <GapsTable items={gapsQuery.data?.items || []} loading={gapsQuery.isLoading} />
    </ConsoleShell>
  );
}

function RecommendationsView() {
  const recsQuery = useComplianceRecommendations({ limit: 100 });
  return (
    <ConsoleShell view="recommendations">
      <Card className="glass-card overflow-hidden">
        <div className="p-4 border-b border-white/5 bg-black/20"><CardTitle className="text-neutral-100 text-base">Deterministic recommendations</CardTitle></div>
        <DataTable headers={['Severity', 'Status', 'Control', 'Recommendation', 'Human review', 'Linked gap']} loading={recsQuery.isLoading} emptyTitle="No recommendations" emptyDescription="Recommendations are derived from existing gaps only.">
          {(recsQuery.data?.items || []).map((rec) => (
            <tr key={rec.id} className="hover:bg-white/[0.02]">
              <td className="p-4"><LabelBadge value={rec.severity} tone={bandTone} /></td>
              <td className="p-4"><LabelBadge value={rec.status} /></td>
              <td className="p-4 text-neutral-300">{safeText(rec.control_code || rec.control_id)}</td>
              <td className="p-4 text-neutral-300 max-w-2xl"><div className="font-medium text-neutral-100">{safeText(rec.title)}</div><div className="text-xs text-neutral-500 mt-1">{safeText(rec.summary)}</div></td>
              <td className="p-4"><LabelBadge value="requires_review" /></td>
              <td className="p-4 font-mono text-xs text-neutral-500">{safeText(rec.gap_id || '-')}</td>
            </tr>
          ))}
        </DataTable>
      </Card>
      <div className="rounded-md border border-amber-500/20 bg-amber-500/10 px-4 py-3 text-sm text-amber-200">Phase 7 intentionally does not provide execute, apply, script, Terraform, or deployment controls.</div>
    </ConsoleShell>
  );
}

function KnowledgeView({ canIngest }: { canIngest: boolean }) {
  const [filters, setFilters] = useState({ source_type: '', trust_level: '', status: 'active' });
  const knowledgeQuery = useKnowledgeDocuments({ ...filters, limit: 100 });
  const ingest = useIngestKnowledge();
  const ingestCurated = async () => {
    try {
      const result = await ingest.mutateAsync({ tenant_scoped: false });
      toast.success('Curated catalog ingestion completed', { description: `${result.documents_seen} documents seen` });
    } catch (err: unknown) {
      toast.error(errorMessage(err));
    }
  };
  return (
    <ConsoleShell view="knowledge">
      <Card className="glass-card">
        <CardContent className="p-4">
          <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 flex-1">
              <FilterSelect label="Source type" value={filters.source_type} onChange={(value) => setFilters((current) => ({ ...current, source_type: value }))} options={[['', 'All sources'], ['framework_summary', 'Framework summary'], ['control_summary', 'Control summary'], ['tenant_note', 'Tenant note']]} />
              <FilterSelect label="Trust level" value={filters.trust_level} onChange={(value) => setFilters((current) => ({ ...current, trust_level: value }))} options={[['', 'Any trust'], ['curated', 'Curated'], ['tenant_curated', 'Tenant curated']]} />
              <FilterSelect label="Status" value={filters.status} onChange={(value) => setFilters((current) => ({ ...current, status: value }))} options={[['', 'Any'], ['active', 'Active'], ['archived', 'Archived']]} />
            </div>
            <Button variant="outline" disabled={!canIngest || ingest.isPending} onClick={ingestCurated}>
              <BookOpen className="h-4 w-4 mr-2" />
              {ingest.isPending ? 'Ingesting' : 'Ingest curated catalog'}
            </Button>
          </div>
          {!canIngest && <div className="mt-3 text-xs text-neutral-500">Curated catalog ingestion is available to admin and owner roles.</div>}
        </CardContent>
      </Card>
      <Card className="glass-card overflow-hidden">
        <div className="p-4 border-b border-white/5 bg-black/20"><CardTitle className="text-neutral-100 text-base">Knowledge sources</CardTitle></div>
        <DataTable headers={['Title', 'Source', 'Trust', 'License', 'Status', 'Chunks', 'Updated']} loading={knowledgeQuery.isLoading} emptyTitle="No knowledge documents" emptyDescription="Use curated ingestion to populate safe summaries.">
          {(knowledgeQuery.data?.items || []).map((document: KnowledgeDocument) => (
            <tr key={document.id} className="hover:bg-white/[0.02]">
              <td className="p-4 text-neutral-100 font-medium">{safeText(document.title)}</td>
              <td className="p-4 text-neutral-400">{safeText(document.source_type)}</td>
              <td className="p-4"><LabelBadge value={document.trust_level} /></td>
              <td className="p-4 text-neutral-400">{safeText(document.license_status)}</td>
              <td className="p-4"><LabelBadge value={document.status} /></td>
              <td className="p-4 text-neutral-300">{document.chunk_count}</td>
              <td className="p-4 text-neutral-400">{dateText(document.updated_at)}</td>
            </tr>
          ))}
        </DataTable>
      </Card>
    </ConsoleShell>
  );
}

function AssistantView() {
  const frameworksQuery = useComplianceFrameworks({ status: 'active', limit: 100 });
  const [question, setQuestion] = useState('');
  const [frameworkId, setFrameworkId] = useState('');
  const [controlId, setControlId] = useState('');
  const ask = useAskCompliance();
  const sessionsQuery = useComplianceAskSessions({ limit: 10 });

  const submit = async () => {
    try {
      await ask.mutateAsync({ question, framework_id: frameworkId || undefined, control_id: controlId || undefined });
      setQuestion('');
    } catch (err: unknown) {
      toast.error(errorMessage(err));
    }
  };

  const answer = ask.data;
  return (
    <ConsoleShell view="assistant">
      <Card className="glass-card">
        <CardContent className="p-5 space-y-4">
          <div className="grid gap-3 lg:grid-cols-[1fr_220px_220px_auto]">
            <div className="space-y-1">
              <label className="text-[10px] uppercase tracking-wider text-neutral-500">Question</label>
              <Input aria-label="Compliance assistant question" value={question} onChange={(event) => setQuestion(event.target.value)} placeholder="Ask about controls, gaps, evidence, or framework posture" />
            </div>
            <FilterSelect label="Framework" value={frameworkId} onChange={setFrameworkId} options={[['', 'Any framework'], ...(frameworksQuery.data || []).map((fw) => [fw.id, fw.key.toUpperCase()] as [string, string])]} />
            <div className="space-y-1">
              <label className="text-[10px] uppercase tracking-wider text-neutral-500">Control ID</label>
              <Input aria-label="Assistant control filter" value={controlId} onChange={(event) => setControlId(event.target.value)} placeholder="Optional UUID" />
            </div>
            <div className="flex items-end"><Button disabled={!question.trim() || ask.isPending} onClick={submit}><MessageSquare className="h-4 w-4 mr-2" />{ask.isPending ? 'Asking' : 'Ask'}</Button></div>
          </div>
        </CardContent>
      </Card>

      {answer && (
        <Card className="glass-card">
          <CardContent className="p-5 space-y-5">
            <div className="flex flex-wrap gap-2">
              <LabelBadge value={answer.refusal_reason ? 'refused' : 'answered'} />
              <Badge variant="outline" className="border-white/10 text-neutral-300">Confidence {pct(answer.confidence * 100)}</Badge>
              <Badge variant="outline" className="border-white/10 text-neutral-300">Session {safeText(answer.session_id)}</Badge>
            </div>
            {answer.refusal_reason && <div className="rounded-md border border-amber-500/20 bg-amber-500/10 px-4 py-3 text-sm text-amber-200">Refusal reason: {safeText(answer.refusal_reason)}</div>}
            <p className="text-sm text-neutral-200 leading-7 whitespace-pre-wrap">{safeText(answer.answer)}</p>
            <div className="grid gap-4 lg:grid-cols-2">
              <SummaryList title="Citations" items={answer.citations} />
              <SummaryList title="Related controls" items={answer.related_controls} />
              <SummaryList title="Related evidence" items={answer.related_evidence} />
              <SummaryList title="Related gaps" items={answer.related_gaps} />
            </div>
            <section>
              <h3 className="text-xs uppercase tracking-wider text-neutral-500 mb-2">Recommended next steps</h3>
              <ul className="space-y-2 text-sm text-neutral-300">
                {answer.recommended_next_steps.map((step) => <li key={step} className="rounded-md border border-white/10 bg-white/[0.02] p-3">{safeText(step)}</li>)}
              </ul>
            </section>
          </CardContent>
        </Card>
      )}

      <Card className="glass-card overflow-hidden">
        <div className="p-4 border-b border-white/5 bg-black/20"><CardTitle className="text-neutral-100 text-base">Recent assistant sessions</CardTitle></div>
        <DataTable headers={['Status', 'Question hash', 'Confidence', 'Trace', 'Created']} loading={sessionsQuery.isLoading} emptyTitle="No assistant sessions" emptyDescription="Ask a question to create a safe session record.">
          {(sessionsQuery.data?.items || []).map((session) => (
            <tr key={session.id} className="hover:bg-white/[0.02]">
              <td className="p-4"><LabelBadge value={session.refused ? 'refused' : 'answered'} /></td>
              <td className="p-4 font-mono text-xs text-neutral-400">{safeText(session.question_hash)}</td>
              <td className="p-4 text-neutral-300">{pct(session.confidence * 100)}</td>
              <td className="p-4 font-mono text-xs text-neutral-500">{safeText(session.retrieval_trace_id || '-')}</td>
              <td className="p-4 text-neutral-400">{dateText(session.created_at)}</td>
            </tr>
          ))}
        </DataTable>
      </Card>
    </ConsoleShell>
  );
}

function SummaryList({ title, items }: { title: string; items: Record<string, unknown>[] }) {
  return (
    <section>
      <h3 className="text-xs uppercase tracking-wider text-neutral-500 mb-2">{title}</h3>
      {items.length === 0 ? (
        <div className="rounded-md border border-white/10 bg-white/[0.02] p-3 text-xs text-neutral-500">No related records returned.</div>
      ) : (
        <div className="space-y-2">
          {items.slice(0, 5).map((item, index) => (
            <div key={index} className="rounded-md border border-white/10 bg-white/[0.02] p-3 text-xs text-neutral-300">
              {Object.entries(item).slice(0, 5).map(([key, value]) => (
                <div key={key}><span className="text-neutral-500">{safeText(key)}:</span> {safeText(value)}</div>
              ))}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function Info({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="rounded-md border border-white/10 bg-white/[0.02] p-3 min-w-0">
      <div className="text-[10px] uppercase tracking-wider text-neutral-500 mb-1">{label}</div>
      <div className={`text-neutral-300 break-words ${mono ? 'font-mono text-xs' : 'text-sm'}`}>{safeText(value)}</div>
    </div>
  );
}

export function ComplianceConsole({
  view = 'overview',
  frameworkId,
  controlId,
}: {
  view?: ConsoleView;
  frameworkId?: string;
  controlId?: string;
}) {
  const { user } = useAuth();
  const canRunAssessment = hasAnyRole(user, ['owner', 'admin', 'auditor', 'analyst']);
  const canReview = hasAnyRole(user, ['owner', 'admin']);
  const canIngest = hasAnyRole(user, ['owner', 'admin']);

  if (view === 'frameworks' || view === 'framework-detail') return <FrameworksView frameworkId={frameworkId} />;
  if (view === 'control-detail') return <ControlDetailView controlId={controlId} canReview={canReview} />;
  if (view === 'evidence') return <EvidenceView />;
  if (view === 'gaps') return <GapsView />;
  if (view === 'recommendations') return <RecommendationsView />;
  if (view === 'knowledge') return <KnowledgeView canIngest={canIngest} />;
  if (view === 'assistant') return <AssistantView />;
  return <Overview canRunAssessment={canRunAssessment} />;
}
