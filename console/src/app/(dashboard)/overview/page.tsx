"use client";

import { ShieldCheck, Activity, AlertTriangle, Network, Server, Cpu, Database, CheckCircle2, XCircle, RefreshCw } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { useDashboardStats, useComplianceDashboard, useGatewayRequests, useProviders, useRemediationApprovals } from '@/hooks/use-data';
import { CardSkeleton } from '@/components/shared/loaders';
import { motion } from 'framer-motion';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';

type GatewayRequestSummary = {
  created_at: string;
  status?: string | null;
};

type ProviderSummary = {
  name: string;
  is_active?: boolean;
};

type TooltipPayload = {
  name?: string | number;
  color?: string;
  value?: string | number;
};

function buildChartData(items: GatewayRequestSummary[]): Array<{ hour: string; allowed: number; blocked: number; redacted: number }> {
  const now = new Date();
  const buckets: Record<string, { allowed: number; blocked: number; redacted: number }> = {};
  for (let i = 11; i >= 0; i--) {
    const d = new Date(now);
    d.setHours(d.getHours() - i, 0, 0, 0);
    const key = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    buckets[key] = { allowed: 0, blocked: 0, redacted: 0 };
  }
  for (const item of items) {
    const d = new Date(item.created_at);
    d.setMinutes(0, 0, 0);
    const key = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    if (!buckets[key]) continue;
    const s = (item.status || '').toLowerCase();
    if (s === 'success' || s === 'allowed' || s === 'completed') buckets[key].allowed++;
    else if (s === 'blocked') buckets[key].blocked++;
    else buckets[key].redacted++;
  }
  return Object.entries(buckets).map(([hour, counts]) => ({ hour, ...counts }));
}

const CustomTooltip = ({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: TooltipPayload[];
  label?: string;
}) => {
  if (active && payload && payload.length) {
    return (
      <div className="glass border border-white/10 rounded-lg p-3 text-xs shadow-2xl">
        <p className="text-neutral-400 mb-2 font-medium border-b border-white/10 pb-1">{label}</p>
        {payload.map((p) => (
          <div key={p.name} className="flex justify-between items-center gap-4 mb-1">
            <div className="flex items-center gap-1.5">
              <div className="w-2 h-2 rounded-full" style={{ backgroundColor: p.color }} />
              <span className="text-neutral-300 capitalize">{p.name}</span>
            </div>
            <span className="font-bold text-neutral-100">{p.value}</span>
          </div>
        ))}
      </div>
    );
  }
  return null;
};

export default function DashboardPage() {
  const { data: stats, isLoading: statsLoading } = useDashboardStats();
  const { data: compliance, isLoading: compLoading } = useComplianceDashboard();
  const { data: gatewayData, isLoading: gatewayLoading } = useGatewayRequests(0, 200);
  const { data: providers } = useProviders();
  const { data: approvalsData } = useRemediationApprovals({ status: 'pending', limit: 25 });

  const isLoading = statsLoading || compLoading;

  if (isLoading) {
    return (
      <div className="space-y-6 max-w-[1600px] mx-auto">
        <div className="flex justify-between items-end">
          <div>
            <h2 className="text-2xl font-bold tracking-tight text-neutral-100">Overview</h2>
            <p className="text-neutral-400">Loading your AI Security posture...</p>
          </div>
        </div>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <CardSkeleton /><CardSkeleton /><CardSkeleton /><CardSkeleton />
        </div>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
          <div className="col-span-4 h-[380px] bg-neutral-900/30 border border-neutral-800 rounded-xl animate-pulse" />
          <div className="col-span-3 h-[380px] bg-neutral-900/30 border border-neutral-800 rounded-xl animate-pulse" />
        </div>
      </div>
    );
  }

  const totalRequests = stats?.audit?.total_events || 0;
  const violations = stats?.audit?.events_by_type?.['policy.violation'] || 0;
  const blocked = stats?.audit?.gateway_by_status?.['blocked'] || stats?.audit?.events_by_type?.['gateway.blocked'] || 0;
  const openApprovals = approvalsData?.items?.filter((approval) => approval.status === 'pending').length ?? 0;

  const chartData = buildChartData((gatewayData?.items || []) as GatewayRequestSummary[]);
  const providerList: ProviderSummary[] = providers && providers.length > 0 ? providers as ProviderSummary[] : [];
  const activeProviders = providerList.filter((provider) => provider.is_active !== false).length;

  return (
    <div className="space-y-6 max-w-[1600px] mx-auto pb-10">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-end gap-4">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-neutral-100 font-sans">System Overview</h2>
          <p className="text-sm text-neutral-400 mt-1">Real-time operational visibility and security posture.</p>
        </div>
        
        <div className="flex items-center gap-4 bg-blue-500/10 border border-blue-500/20 px-4 py-2 rounded-lg">
          <div className="flex items-center gap-2">
            <span className="relative flex h-2.5 w-2.5">
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-blue-500"></span>
            </span>
            <span className="text-sm font-medium text-blue-300">Evidence-supported posture</span>
          </div>
          <div className="h-4 w-[1px] bg-blue-500/20" />
          <div className="flex gap-3 text-xs text-blue-300/80">
            <span className="flex items-center gap-1"><Server className="w-3 h-3" /> Providers: {activeProviders}/{providerList.length}</span>
            <span className="flex items-center gap-1"><Database className="w-3 h-3" /> Audit events: {totalRequests}</span>
            <span className="flex items-center gap-1"><Cpu className="w-3 h-3" /> Approvals: {openApprovals}</span>
          </div>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
          <Card className="glass-card">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-neutral-400">Total Gateway Traffic</CardTitle>
              <Activity className="h-4 w-4 text-blue-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-neutral-100">{totalRequests.toLocaleString()}</div>
              <p className="text-xs text-neutral-500 mt-1">Processed requests</p>
            </CardContent>
          </Card>
        </motion.div>
        
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }}>
          <Card className="glass-card border-amber-500/20">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-amber-500">Violations Detected</CardTitle>
              <AlertTriangle className="h-4 w-4 text-amber-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-amber-500">{violations.toLocaleString()}</div>
              <p className="text-xs text-amber-500/60 mt-1">Awaiting review in Action Center</p>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
          <Card className="glass-card border-red-500/20">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-red-400">Blocked Intercepts</CardTitle>
              <ShieldCheck className="h-4 w-4 text-red-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-red-500">{blocked.toLocaleString()}</div>
              <p className="text-xs text-red-500/60 mt-1">Egress prevented by policy</p>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.25 }}>
          <Card className="glass-card">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-neutral-400">Open Approvals</CardTitle>
              <Network className="h-4 w-4 text-emerald-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-neutral-100">{openApprovals}</div>
              <p className="text-xs text-neutral-500 mt-1">Human review queue</p>
            </CardContent>
          </Card>
        </motion.div>
      </div>

      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-7">
        {/* Live Gateway Activity Chart */}
        <Card className="col-span-4 glass-card flex flex-col">
          <CardHeader className="border-b border-white/5 pb-4">
            <CardTitle className="text-neutral-100 flex items-center gap-2">
              <Activity className="w-5 h-5 text-blue-500" />
              Gateway Traffic Telemetry
            </CardTitle>
            <p className="text-xs text-neutral-500">Real-time rolling 12-hour egress volume</p>
          </CardHeader>
          <CardContent className="pt-6 flex-1">
            {gatewayLoading ? (
              <div className="h-[280px] flex items-center justify-center text-neutral-500 text-sm">
                <RefreshCw className="w-5 h-5 animate-spin mr-2" />
                Aggregating telemetry...
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={280}>
                <AreaChart data={chartData} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="gradAllowed" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="var(--color-primary)" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="var(--color-primary)" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="gradBlocked" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="var(--color-destructive)" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="var(--color-destructive)" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                  <XAxis
                    dataKey="hour"
                    tick={{ fontSize: 11, fill: '#737373' }}
                    axisLine={false}
                    tickLine={false}
                    interval={2}
                    dy={10}
                  />
                  <YAxis
                    tick={{ fontSize: 11, fill: '#737373' }}
                    axisLine={false}
                    tickLine={false}
                    allowDecimals={false}
                    dx={-10}
                  />
                  <Tooltip content={<CustomTooltip />} />
                  <Legend
                    iconType="circle"
                    iconSize={8}
                    wrapperStyle={{ fontSize: '12px', color: '#a3a3a3', paddingTop: '16px' }}
                  />
                  <Area
                    type="monotone"
                    dataKey="allowed"
                    name="Allowed"
                    stroke="var(--color-primary)"
                    strokeWidth={2}
                    fill="url(#gradAllowed)"
                    dot={false}
                    activeDot={{ r: 4, strokeWidth: 0, fill: "var(--color-primary)" }}
                  />
                  <Area
                    type="monotone"
                    dataKey="blocked"
                    name="Blocked"
                    stroke="var(--color-destructive)"
                    strokeWidth={2}
                    fill="url(#gradBlocked)"
                    dot={false}
                    activeDot={{ r: 4, strokeWidth: 0, fill: "var(--color-destructive)" }}
                  />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        <div className="col-span-3 flex flex-col gap-6">
          {/* Security Posture Summary */}
          <Card className="glass-card flex-1">
            <CardHeader className="border-b border-white/5 pb-4">
              <CardTitle className="text-neutral-100 flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-emerald-500" />
                Security Posture Summary
              </CardTitle>
              <p className="text-xs text-neutral-500">Live framework alignment scoring</p>
            </CardHeader>
            <CardContent className="pt-6 flex flex-col gap-5">
              {['soc2', 'gdpr', 'hipaa'].map((fw) => {
                const fwData = compliance?.[fw];
                const score = fwData?.score ?? 0;
                
                let colorClass = 'bg-red-500';
                let textClass = 'text-red-400';
                let statusText = 'Critical Risk';
                
                if (score >= 90) {
                  colorClass = 'bg-emerald-500';
                  textClass = 'text-emerald-400';
                  statusText = 'Evidence Supported';
                } else if (score >= 70) {
                  colorClass = 'bg-amber-500';
                  textClass = 'text-amber-400';
                  statusText = 'At Risk';
                } else if (fwData?.status === 'not_calculated') {
                  colorClass = 'bg-neutral-600';
                  textClass = 'text-neutral-400';
                  statusText = 'Unmeasured';
                }

                return (
                  <div key={fw} className="space-y-2">
                    <div className="flex items-center justify-between text-sm">
                      <span className="font-semibold text-neutral-200 uppercase tracking-wider">{fw}</span>
                      <div className="flex items-center gap-2">
                        <span className={`text-xs px-2 py-0.5 rounded bg-neutral-800 ${textClass} bg-opacity-30 border border-current`}>
                          {statusText}
                        </span>
                        <span className={`font-mono font-bold ${textClass}`}>
                          {fwData?.status === 'not_calculated' ? '---' : `${score}%`}
                        </span>
                      </div>
                    </div>
                    <div className="h-2 w-full bg-neutral-800/50 rounded-full overflow-hidden shadow-inner border border-black/20">
                      <div
                        className={`h-full ${colorClass} transition-all duration-1000 ease-out relative`}
                        style={{ width: `${score}%` }}
                      >
                        <div className="absolute inset-0 bg-white/20 w-full animate-[shimmer_2s_infinite]"></div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </CardContent>
          </Card>

          {/* Provider Health Monitoring Cards */}
          <Card className="glass-card">
            <CardHeader className="border-b border-white/5 pb-3">
              <CardTitle className="text-sm text-neutral-100 flex items-center gap-2">
                <Server className="w-4 h-4 text-blue-400" />
                Provider Health
              </CardTitle>
            </CardHeader>
            <CardContent className="pt-4 grid grid-cols-2 gap-3">
              {providerList.length === 0 ? (
                <div className="col-span-2 rounded-lg border border-dashed border-white/10 bg-black/20 p-4 text-sm text-neutral-400">
                  No model providers configured yet. Add provider credentials in Settings before routing live gateway traffic.
                </div>
              ) : providerList.slice(0, 4).map((p) => (
                <div key={p.name} className="flex items-center justify-between p-3 rounded-lg bg-neutral-800/30 border border-white/5">
                  <span className="text-sm font-medium text-neutral-300">{p.name}</span>
                  {p.is_active !== false ? (
                    <div className="flex items-center gap-1.5 text-xs text-emerald-400">
                      <CheckCircle2 className="w-3.5 h-3.5" /> <span className="hidden xl:inline">Healthy</span>
                    </div>
                  ) : (
                    <div className="flex items-center gap-1.5 text-xs text-neutral-500">
                      <XCircle className="w-3.5 h-3.5" /> <span className="hidden xl:inline">Disabled</span>
                    </div>
                  )}
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
