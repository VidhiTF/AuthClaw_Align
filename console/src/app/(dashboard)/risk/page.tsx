"use client";

import { useMemo, useState } from 'react';
import { Activity, FlaskConical, Link2, Play, ShieldAlert, ShieldCheck } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardTitle } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { EmptyState } from '@/components/shared/states';
import { useAuth } from '@/hooks/use-auth';
import {
  useCreateRiskProbeRun,
  useRiskPosture,
  useRiskProbeRuns,
  useRiskVulnerabilities,
  useSeedRiskDemoData,
} from '@/hooks/use-data';
import type { RiskProbeCategory } from '@/hooks/use-data';

const categories: Array<[RiskProbeCategory | '', string]> = [
  ['', 'All categories'],
  ['prompt_injection', 'Prompt injection'],
  ['data_disclosure', 'Data disclosure'],
  ['credential_leakage', 'Credential leakage'],
  ['harmful_content', 'Harmful content'],
  ['sycophancy_policy_bypass', 'Sycophancy / policy bypass'],
  ['policy_bypass', 'Policy bypass'],
  ['report_export_leakage', 'Report/export leakage'],
];

const severities = ['', 'critical', 'high', 'medium', 'low'];
const statuses = ['', 'open', 'triaged', 'remediating', 'accepted_risk', 'resolved', 'false_positive'];

function label(value?: string | null) {
  if (!value) return 'None';
  return value.replace(/_/g, ' ').replace(/\b\w/g, (char) => char.toUpperCase());
}

function toneForSeverity(severity?: string) {
  if (severity === 'critical') return 'border-red-500/30 bg-red-500/10 text-red-300';
  if (severity === 'high') return 'border-orange-500/30 bg-orange-500/10 text-orange-300';
  if (severity === 'medium') return 'border-amber-500/30 bg-amber-500/10 text-amber-300';
  return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300';
}

function toneForVerdict(verdict?: string) {
  if (verdict === 'no_go') return 'border-red-500/30 bg-red-500/10 text-red-300';
  if (verdict === 'needs_review') return 'border-amber-500/30 bg-amber-500/10 text-amber-300';
  return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300';
}

function formatDate(value?: string | null) {
  if (!value) return 'Not recorded';
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value));
}

type RoleAwareUser = { role?: string; role_name?: string; roles?: string[] };

function rolesFor(user: unknown): string[] {
  const roleUser = user as RoleAwareUser | null | undefined;
  return [
    roleUser?.role,
    roleUser?.role_name,
    ...(Array.isArray(roleUser?.roles) ? roleUser.roles : []),
  ].filter((role): role is string => typeof role === 'string' && role.length > 0).map((role) => role.toLowerCase());
}

function hasAnyRole(user: unknown, allowed: string[]) {
  return rolesFor(user).some((role) => allowed.includes(role));
}

function Metric({ label: metricLabel, value, hint }: { label: string; value: string | number; hint: string }) {
  return (
    <Card className="glass-card">
      <CardContent className="p-5">
        <div className="text-xs uppercase tracking-wide text-neutral-500">{metricLabel}</div>
        <div className="mt-3 text-2xl font-semibold text-neutral-100">{value}</div>
        <div className="mt-2 text-xs text-neutral-500">{hint}</div>
      </CardContent>
    </Card>
  );
}

function errorMessage(error: unknown) {
  const response = (error as { response?: { status?: number } })?.response;
  if (response?.status === 404) return 'Risk data is unavailable for this tenant yet. Refresh after backend seeding or probe execution.';
  if (response?.status === 403) return 'Your role can view risk posture but cannot run or update risk data.';
  if (response?.status === 401) return 'Please sign in again before using Risk & Red Teaming actions.';
  return 'Risk action failed. Check backend health and try again.';
}

export default function RiskPage() {
  const { user } = useAuth();
  const [category, setCategory] = useState('');
  const [severity, setSeverity] = useState('');
  const [status, setStatus] = useState('');
  const [notice, setNotice] = useState('');

  const probeParams = useMemo(() => ({ category: category || undefined, limit: 50 }), [category]);
  const vulnerabilityParams = useMemo(
    () => ({ category: category || undefined, severity: severity || undefined, status: status || undefined, limit: 50 }),
    [category, severity, status],
  );

  const postureQuery = useRiskPosture();
  const probeQuery = useRiskProbeRuns(probeParams);
  const vulnerabilityQuery = useRiskVulnerabilities(vulnerabilityParams);
  const seedDemo = useSeedRiskDemoData();
  const createProbe = useCreateRiskProbeRun();

  const posture = postureQuery.data;
  const probes = probeQuery.data?.items ?? [];
  const vulnerabilities = vulnerabilityQuery.data?.items ?? [];
  const coveredCategories = posture?.counts?.probe_categories_covered?.length ?? 0;
  const canRunProbes = hasAnyRole(user, ['owner', 'admin', 'analyst', 'security_admin']);
  const canSeedDemo = canRunProbes;

  async function handleSeedDemo() {
    setNotice('');
    try {
      const result = await seedDemo.mutateAsync();
      setNotice(`Safe demo ready: ${result.probe_runs_created ?? 0} probe runs and ${result.vulnerabilities_created ?? 0} register rows created.`);
    } catch (error) {
      setNotice(errorMessage(error));
    }
  }

  async function handleCreateProbe() {
    setNotice('');
    const selectedCategory = (category || 'prompt_injection') as RiskProbeCategory;
    try {
      await createProbe.mutateAsync({
        name: `${label(selectedCategory)} simulated probe`,
        category: selectedCategory,
        target_surface: 'gateway',
        model_target: 'route-selected model',
      });
      setNotice('Simulated probe completed. No external target was executed.');
    } catch (error) {
      setNotice(errorMessage(error));
    }
  }

  return (
    <div className="space-y-6 max-w-[1600px] mx-auto pb-10">
      <div className="flex flex-col xl:flex-row xl:items-end justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-neutral-100 font-sans flex items-center gap-2">
            <FlaskConical className="w-6 h-6 text-amber-400" />
            Risk & Red Teaming
          </h2>
          <p className="text-sm text-neutral-400 mt-1">Evidence-supported adversarial posture, vulnerability register, and go/no-go summary.</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant="outline" className="bg-emerald-500/10 text-emerald-300 border-emerald-500/20">Simulated by default</Badge>
          {canSeedDemo && (
            <Button variant="outline" onClick={handleSeedDemo} disabled={seedDemo.isPending}>
              <ShieldCheck className="w-4 h-4" />
              Seed demo
            </Button>
          )}
          {canRunProbes ? (
            <Button onClick={handleCreateProbe} disabled={createProbe.isPending}>
              <Play className="w-4 h-4" />
              Run simulated probe
            </Button>
          ) : (
            <Badge variant="outline" className="border-amber-500/20 bg-amber-500/10 text-amber-300">Read-only role</Badge>
          )}
        </div>
      </div>

      {notice && <div className="rounded-md border border-emerald-500/20 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-200">{notice}</div>}

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <Metric label="Go / no-go" value={label(posture?.verdict)} hint="Evidence-supported posture, auditor review required" />
        <Metric label="Probe runs" value={posture?.counts?.probe_runs ?? 0} hint={`${coveredCategories} categories covered`} />
        <Metric label="Open high+" value={(posture?.counts?.open_high ?? 0) + (posture?.counts?.open_critical ?? 0)} hint="Requires owner review before go-live" />
        <Metric label="Vulnerabilities" value={posture?.counts?.vulnerabilities ?? 0} hint="Tenant-scoped register rows" />
      </div>

      <Card className="glass-card">
        <div className="p-4 border-b border-white/5 bg-black/20 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-amber-400" />
            <CardTitle className="text-neutral-100 text-base">Filters</CardTitle>
          </div>
          <div className="grid gap-3 sm:grid-cols-3 w-full lg:w-auto">
            <select className="h-9 rounded-md border border-white/10 bg-neutral-950 px-3 text-sm text-neutral-100" value={category} onChange={(event) => setCategory(event.target.value)}>
              {categories.map(([value, name]) => <option key={value || 'all'} value={value}>{name}</option>)}
            </select>
            <select className="h-9 rounded-md border border-white/10 bg-neutral-950 px-3 text-sm text-neutral-100" value={severity} onChange={(event) => setSeverity(event.target.value)}>
              {severities.map((value) => <option key={value || 'all'} value={value}>{value ? label(value) : 'All severities'}</option>)}
            </select>
            <select className="h-9 rounded-md border border-white/10 bg-neutral-950 px-3 text-sm text-neutral-100" value={status} onChange={(event) => setStatus(event.target.value)}>
              {statuses.map((value) => <option key={value || 'all'} value={value}>{value ? label(value) : 'All statuses'}</option>)}
            </select>
          </div>
        </div>
      </Card>

      <div className="grid gap-6 2xl:grid-cols-[1.15fr_0.85fr]">
        <Card className="glass-card">
          <div className="p-4 border-b border-white/5 bg-black/20 flex items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <FlaskConical className="w-4 h-4 text-blue-400" />
              <CardTitle className="text-neutral-100 text-base">Adversarial Probe Runs</CardTitle>
            </div>
            <Badge variant="outline" className="border-white/10 text-neutral-300">{probeQuery.data?.total ?? 0} rows</Badge>
          </div>
          <CardContent className="p-0">
            {probes.length ? (
              <Table>
                <TableHeader>
                  <TableRow className="border-white/5 bg-white/[0.02]">
                    <TableHead>Name</TableHead>
                    <TableHead>Category</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Score</TableHead>
                    <TableHead>Blocked</TableHead>
                    <TableHead>Results</TableHead>
                    <TableHead>Mode</TableHead>
                    <TableHead>Completed</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {probes.map((probe) => (
                    <TableRow key={probe.id} className="border-white/5">
                      <TableCell className="font-medium text-neutral-100">{probe.name}</TableCell>
                      <TableCell className="text-neutral-300">{label(String(probe.category))}</TableCell>
                      <TableCell><Badge variant="outline" className="border-blue-500/20 bg-blue-500/10 text-blue-300">{label(String(probe.status))}</Badge></TableCell>
                      <TableCell className="text-neutral-300">{probe.risk_score}</TableCell>
                      <TableCell className="text-neutral-300">{probe.blocked_count}/{probe.probes_total}</TableCell>
                      <TableCell className="text-neutral-300">{probe.results?.length ?? 0}</TableCell>
                      <TableCell className="text-neutral-300">{label(probe.execution_mode)}</TableCell>
                      <TableCell className="text-neutral-400">{formatDate(probe.completed_at)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <EmptyState
                title="No probe runs"
                description="Safe simulated runs appear here after demo seeding or manual simulation."
                icon={FlaskConical}
              />
            )}
          </CardContent>
        </Card>

        <Card className="glass-card">
          <div className="p-4 border-b border-white/5 bg-black/20 flex items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-orange-400" />
              <CardTitle className="text-neutral-100 text-base">Go / No-Go Posture</CardTitle>
            </div>
            <Badge variant="outline" className={toneForVerdict(posture?.verdict)}>{label(posture?.verdict)}</Badge>
          </div>
          <CardContent className="p-5 space-y-5">
            <p className="text-sm leading-6 text-neutral-300">{posture?.summary ?? 'No posture snapshot has been generated yet.'}</p>
            <div>
              <div className="text-xs uppercase tracking-wide text-neutral-500 mb-2">Evidence</div>
              <p className="text-sm leading-6 text-neutral-400">{posture?.evidence_summary ?? 'Awaiting sanitized probe and register evidence.'}</p>
            </div>
            <div>
              <div className="text-xs uppercase tracking-wide text-neutral-500 mb-2">Blockers</div>
              <div className="space-y-2">
                {(posture?.blockers ?? []).length ? posture?.blockers.map((blocker, index) => (
                  <div key={`${blocker.id ?? index}`} className="rounded-md border border-white/10 bg-black/20 p-3">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-sm text-neutral-100">{String(blocker.title ?? 'Needs review')}</span>
                      <Badge variant="outline" className={toneForSeverity(String(blocker.severity ?? 'medium'))}>{label(String(blocker.severity ?? 'medium'))}</Badge>
                    </div>
                    <div className="mt-1 text-xs text-neutral-500">{label(String(blocker.status ?? 'open'))}</div>
                  </div>
                )) : <p className="text-sm text-neutral-500">No high or critical blockers in the current snapshot.</p>}
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card className="glass-card">
        <div className="p-4 border-b border-white/5 bg-black/20 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-red-400" />
            <CardTitle className="text-neutral-100 text-base">Vulnerability Register</CardTitle>
          </div>
          <Badge variant="outline" className="border-white/10 text-neutral-300">{vulnerabilityQuery.data?.total ?? 0} rows</Badge>
        </div>
        <CardContent className="p-0">
          {vulnerabilities.length ? (
            <Table>
              <TableHeader>
                <TableRow className="border-white/5 bg-white/[0.02]">
                  <TableHead>Severity</TableHead>
                  <TableHead>Title</TableHead>
                  <TableHead>Category</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Confidence</TableHead>
                  <TableHead>Owner</TableHead>
                  <TableHead>Remediation</TableHead>
                  <TableHead>Evidence</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {vulnerabilities.map((item) => (
                  <TableRow key={item.id} className="border-white/5">
                    <TableCell><Badge variant="outline" className={toneForSeverity(String(item.severity))}>{label(String(item.severity))}</Badge></TableCell>
                    <TableCell className="min-w-[260px] whitespace-normal">
                      <div className="font-medium text-neutral-100">{item.title}</div>
                      <div className="mt-1 text-xs text-neutral-500">{item.description}</div>
                    </TableCell>
                    <TableCell className="text-neutral-300">{label(String(item.category))}</TableCell>
                    <TableCell className="text-neutral-300">{label(String(item.status))}</TableCell>
                    <TableCell className="text-neutral-300">{item.confidence}%</TableCell>
                    <TableCell className="text-neutral-400">{item.owner_user_id ? item.owner_user_id.slice(0, 8) : 'Unassigned'}</TableCell>
                    <TableCell className="text-neutral-300">
                      <div className="flex items-center gap-2">
                        {item.remediation_plan_id && <Link2 className="w-3.5 h-3.5 text-blue-400" />}
                        <span>{item.remediation_summary ?? 'Needs remediation linkage review'}</span>
                      </div>
                    </TableCell>
                    <TableCell className="min-w-[240px] whitespace-normal text-neutral-400">{item.evidence_summary}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <EmptyState
              title="No vulnerabilities"
              description="Tenant-scoped register rows appear here when simulated probes detect evidence-supported risk."
              icon={ShieldAlert}
            />
          )}
        </CardContent>
      </Card>

      <Card className="glass-card">
        <div className="p-4 border-b border-white/5 bg-black/20 flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          <CardTitle className="text-neutral-100 text-base">Recommended Guardrails</CardTitle>
        </div>
        <CardContent className="p-5 grid gap-3 md:grid-cols-3">
          {(posture?.recommendations ?? [
            'Keep probe execution simulated by default.',
            'Link high and critical issues to remediation evidence.',
            'Review route and policy changes before go-live.',
          ]).map((item, index) => (
            <div key={`${index}-${String(item)}`} className="rounded-md border border-white/10 bg-black/20 p-4 text-sm leading-6 text-neutral-300">
              {String(item)}
            </div>
          ))}
        </CardContent>
      </Card>

      <div className="sr-only">No raw provider payloads, Vault references, credentials, or legal assurance copy is displayed.</div>
    </div>
  );
}
