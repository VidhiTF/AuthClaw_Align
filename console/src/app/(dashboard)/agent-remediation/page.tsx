"use client";

import Link from 'next/link';
import { Bot, FileSearch, ShieldCheck, TimerReset, Workflow, Wrench } from 'lucide-react';
import { Card, CardContent, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  useRemediationApprovals,
  useRemediationDryRuns,
  useRemediationJobs,
  useRemediationPlans,
  useRemediationVerificationResults,
} from '@/hooks/use-data';

const consoleLinks = [
  ['Assistant', '/agent', Bot, 'Conversational assistant for policy, posture, and remediation questions.'],
  ['Scan results', '/findings', FileSearch, 'Security findings and mapped control evidence.'],
  ['Plans', '/remediation/plans', Wrench, 'Deterministic remediation plans and redacted artifacts.'],
  ['Approval queue', '/remediation/approvals', ShieldCheck, 'HITL approval workflow with MFA-required execution messaging.'],
] as const;

export default function AgentRemediationPage() {
  const { data: plans } = useRemediationPlans({ limit: 25 });
  const { data: approvals } = useRemediationApprovals({ limit: 25 });
  const { data: dryRuns } = useRemediationDryRuns({ limit: 25 });
  const { data: jobs } = useRemediationJobs({ limit: 25 });
  const { data: verification } = useRemediationVerificationResults({ limit: 25 });

  const pendingApprovals = approvals?.items?.filter((item) => item.status === 'pending').length ?? 0;
  const approvedApprovals = approvals?.items?.filter((item) => item.status === 'approved').length ?? 0;
  const executingJobs = jobs?.items?.filter((item) => item.status === 'executing').length ?? 0;
  const completedJobs = jobs?.items?.filter((item) => ['succeeded', 'failed', 'disabled'].includes(String(item.status))).length ?? 0;
  const metrics = [
    { label: 'Plans', value: plans?.total ?? 0, Icon: Wrench },
    { label: 'Pending approvals', value: pendingApprovals, Icon: ShieldCheck },
    { label: 'Dry runs', value: dryRuns?.total ?? 0, Icon: TimerReset },
    { label: 'Verification results', value: verification?.total ?? 0, Icon: FileSearch },
  ];

  return (
    <div className="space-y-6 max-w-[1600px] mx-auto pb-10">
      <div className="flex flex-col md:flex-row items-start md:items-end justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-neutral-100 font-sans flex items-center gap-2">
            <Wrench className="w-6 h-6 text-blue-400" />
            Agent & Remediation
          </h2>
          <p className="text-sm text-neutral-400 mt-1">Assistant, scan results, remediation plans, dry-run visibility, and human approval queue.</p>
        </div>
        <Badge variant="outline" className="bg-blue-500/10 text-blue-300 border-blue-500/20">Safe execution only</Badge>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        {metrics.map(({ label, value, Icon }) => (
          <Card key={label} className="glass-card">
            <CardContent className="p-4 flex items-center justify-between">
              <div>
                <p className="text-xs uppercase tracking-wider text-neutral-500">{label}</p>
                <p className="mt-1 text-2xl font-bold text-neutral-100">{value}</p>
              </div>
              <Icon className="w-5 h-5 text-neutral-500" />
            </CardContent>
          </Card>
        ))}
      </div>

      <Card className="glass-card border-amber-500/20">
        <CardContent className="p-4 flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
          <div>
            <p className="text-sm font-semibold text-neutral-100">Execution guardrails</p>
            <p className="mt-1 text-xs text-neutral-400">Real destructive execution controls are absent. Approval expiry and MFA-required messaging stay visible before any future controlled execution phase.</p>
          </div>
          <Badge variant="outline" className="bg-amber-500/10 text-amber-300 border-amber-500/20">
            Approval expiry visible in queue
          </Badge>
        </CardContent>
      </Card>

      <Card className="glass-card overflow-hidden">
        <div className="p-4 border-b border-white/5 bg-black/20 flex items-center gap-2">
          <Workflow className="h-4 w-4 text-blue-400" />
          <CardTitle className="text-neutral-100 text-base">End-to-end approval workflow</CardTitle>
        </div>
        <CardContent className="p-4">
          <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-6">
            {[
              { label: 'Pending', value: pendingApprovals, description: 'Approval awaits review' },
              { label: 'User reviews', value: pendingApprovals + approvedApprovals, description: 'Plan and evidence checked' },
              { label: 'MFA confirmation', value: approvedApprovals, description: 'Elevated approval MFA visible' },
              { label: 'Approved', value: approvedApprovals, description: 'Approval decision recorded' },
              { label: 'Executing', value: executingJobs, description: 'Safe simulated/no-op job status' },
              { label: 'Success / Failure', value: completedJobs, description: 'Terminal job outcome visible' },
            ].map((state) => (
              <div key={state.label} className="rounded-md border border-white/10 bg-white/[0.02] p-3">
                <p className="text-xs uppercase tracking-wider text-neutral-500">{state.label}</p>
                <p className="mt-2 text-2xl font-semibold text-neutral-100">{state.value}</p>
                <p className="mt-1 text-xs leading-5 text-neutral-500">{state.description}</p>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-4 md:grid-cols-2">
        {consoleLinks.map(([title, href, Icon, description]) => (
          <Card key={href} className="glass-card">
            <CardContent className="p-5 flex items-start justify-between gap-4">
              <div className="flex gap-4">
                <div className="w-10 h-10 rounded-md border border-white/10 bg-white/5 flex items-center justify-center">
                  <Icon className="w-5 h-5 text-blue-300" />
                </div>
                <div>
                  <CardTitle className="text-base text-neutral-100">{title}</CardTitle>
                  <p className="mt-2 text-sm leading-6 text-neutral-400">{description}</p>
                </div>
              </div>
              <Link
                href={href}
                className="inline-flex h-9 items-center justify-center rounded-md border border-white/10 bg-black/20 px-3 text-sm text-neutral-200 hover:bg-white/10"
              >
                Open
              </Link>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
