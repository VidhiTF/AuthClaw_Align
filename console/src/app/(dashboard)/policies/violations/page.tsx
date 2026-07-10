"use client";

import { AlertTriangle, Clock, ShieldAlert, CheckCircle } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { usePolicyViolations } from '@/hooks/use-data';

type PolicyViolation = {
  id?: string;
  created_at: string;
  resolved_at?: string | null;
  policy_name?: string | null;
  rule_name?: string | null;
  severity?: string | null;
  action_taken?: string | null;
  details?: string | null;
  metadata?: {
    policy_name?: string;
    rule_name?: string;
    severity?: string;
    action?: string;
    details?: string;
    message?: string;
  } | null;
};

export default function ViolationsPage() {
  const { data: violations = [], isLoading: loading } = usePolicyViolations(0, 100);

  const getSeverityBadge = (severity?: string | null) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return <Badge className="bg-red-500/10 text-red-500 border-red-500/20">Critical</Badge>;
      case 'high':
        return <Badge className="bg-orange-500/10 text-orange-500 border-orange-500/20">High</Badge>;
      case 'medium':
        return <Badge className="bg-amber-500/10 text-amber-500 border-amber-500/20">Medium</Badge>;
      case 'low':
        return <Badge className="bg-blue-500/10 text-blue-500 border-blue-500/20">Low</Badge>;
      default:
        return <Badge className="bg-neutral-500/10 text-neutral-400 border-neutral-500/20">{severity || 'Medium'}</Badge>;
    }
  };

  const getActionBadge = (action?: string | null) => {
    switch (action?.toLowerCase()) {
      case 'blocked':
        return <Badge className="bg-red-500/10 text-red-400 border-red-500/20">Blocked</Badge>;
      case 'redacted':
        return <Badge className="bg-amber-500/10 text-amber-400 border-amber-500/20">Redacted</Badge>;
      case 'logged':
        return <Badge className="bg-blue-500/10 text-blue-400 border-blue-500/20">Logged</Badge>;
      default:
        return <Badge className="bg-neutral-500/10 text-neutral-400 border-neutral-500/20">{action || 'logged'}</Badge>;
    }
  };

  const typedViolations = violations as PolicyViolation[];
  const unresolvedCount = typedViolations.filter((v) => !v.resolved_at).length;
  const resolvedCount = typedViolations.filter((v) => !!v.resolved_at).length;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">Policy Violations</h2>
        <p className="text-neutral-400">Review all detected policy violations across gateway traffic.</p>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <Card className="bg-neutral-900 border-neutral-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-neutral-400">Total Violations</CardTitle>
            <AlertTriangle className="h-4 w-4 text-amber-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-neutral-100">{typedViolations.length}</div>
          </CardContent>
        </Card>
        <Card className="bg-neutral-900 border-neutral-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-neutral-400">Unresolved</CardTitle>
            <ShieldAlert className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-400">{unresolvedCount}</div>
          </CardContent>
        </Card>
        <Card className="bg-neutral-900 border-neutral-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-neutral-400">Resolved</CardTitle>
            <CheckCircle className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-400">{resolvedCount}</div>
          </CardContent>
        </Card>
      </div>

      <Card className="bg-neutral-900 border-neutral-800">
        <CardHeader>
          <CardTitle className="text-neutral-100">Violation History</CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center py-12 text-neutral-500">Loading...</div>
          ) : typedViolations.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-neutral-500">
              <ShieldAlert className="w-10 h-10 mb-3 opacity-40" />
              <p>No violations detected.</p>
              <p className="text-xs mt-1">Violations will appear here when gateway traffic triggers policy rules.</p>
            </div>
          ) : (
            <div className="rounded-md border border-neutral-800 overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-neutral-800 bg-neutral-800/50">
                    <th className="text-left p-3 text-neutral-400 font-medium">Timestamp</th>
                    <th className="text-left p-3 text-neutral-400 font-medium">Policy / Rule</th>
                    <th className="text-left p-3 text-neutral-400 font-medium">Severity</th>
                    <th className="text-left p-3 text-neutral-400 font-medium">Action Taken</th>
                    <th className="text-left p-3 text-neutral-400 font-medium">Status</th>
                    <th className="text-left p-3 text-neutral-400 font-medium">Details</th>
                  </tr>
                </thead>
                <tbody>
                  {typedViolations.map((v, i) => (
                    <tr key={v.id || i} className="border-b border-neutral-800 hover:bg-neutral-800/30">
                      <td className="p-3 text-neutral-400 text-xs">
                        <div className="flex items-center gap-2">
                          <Clock className="w-3 h-3" />
                          {new Date(v.created_at).toLocaleString()}
                        </div>
                      </td>
                      <td className="p-3">
                        <div className="text-neutral-200">{v.policy_name || v.metadata?.policy_name || 'N/A'}</div>
                        <div className="text-neutral-500 text-xs">{v.rule_name || v.metadata?.rule_name || ''}</div>
                      </td>
                      <td className="p-3">{getSeverityBadge(v.severity || v.metadata?.severity)}</td>
                      <td className="p-3">{getActionBadge(v.action_taken || v.metadata?.action || 'logged')}</td>
                      <td className="p-3">
                        {v.resolved_at
                          ? <Badge className="bg-green-500/10 text-green-500 border-green-500/20">Resolved</Badge>
                          : <Badge className="bg-red-500/10 text-red-400 border-red-500/20">Open</Badge>
                        }
                      </td>
                      <td className="p-3 text-neutral-400 text-xs max-w-xs truncate">
                        {v.details || v.metadata?.details || v.metadata?.message || '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
