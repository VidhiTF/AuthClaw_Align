"use client";

import React, { useState } from 'react';
import { Clock, Search, Filter, Download, ShieldCheck, Link2, Database, Key, AlertTriangle, CheckCircle2, RefreshCw } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { useAuditIntegrityVerification, useAuditLogs } from '@/hooks/use-data';
import { apiClient } from '@/lib/api-client';
import { EmptyState, ErrorState } from '@/components/shared/states';
import { TableSkeleton } from '@/components/shared/loaders';
import { motion, AnimatePresence } from 'framer-motion';

type AuditEvent = {
  id: string;
  created_at: string;
  event_type: string;
  action?: string | null;
  resource?: string | null;
  resource_id?: string | null;
  user_id?: string | null;
  metadata?: Record<string, unknown> | null;
  previous_hash?: string | null;
  integrity_hash?: string | null;
};
type AuditRecordVerification = {
  status: string;
  record_verified: boolean;
  scanned_records: number;
  missing_records: number;
  tampered_records: number;
  chain_breaks: number;
};

export default function AuditPage() {
  const [search, setSearch] = useState('');
  const [eventTypeFilter, setEventTypeFilter] = useState('');
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);
  const [recordVerification, setRecordVerification] = useState<Record<string, AuditRecordVerification>>({});
  const [verifyingRecordId, setVerifyingRecordId] = useState<string | null>(null);
  const { data, isLoading: loading, error } = useAuditLogs(0, 100, eventTypeFilter || undefined);
  const verification = useAuditIntegrityVerification();
  
  const events = data?.items || [];
  const eventTypes = Array.from(new Set((events as AuditEvent[]).map((event) => event.event_type).filter(Boolean))).sort();

  const filteredEvents = (events as AuditEvent[]).filter((e) =>
    search === '' || 
    e.event_type?.toLowerCase().includes(search.toLowerCase()) ||
    e.action?.toLowerCase().includes(search.toLowerCase()) ||
    e.resource?.toLowerCase().includes(search.toLowerCase())
  );

  const getEventTypeBadge = (type: string) => {
    const colors: Record<string, string> = {
      'gateway.request': 'bg-blue-500/10 text-blue-400 border-blue-500/20',
      'policy.violation': 'bg-amber-500/10 text-amber-400 border-amber-500/20',
      'auth.login': 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
      'auth.signup': 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
      'policy.created': 'bg-purple-500/10 text-purple-400 border-purple-500/20',
      'admin.provider_created': 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
    };
    return <Badge className={`font-mono text-[10px] uppercase tracking-wider ${colors[type] || 'bg-neutral-500/10 text-neutral-400 border-neutral-500/20'}`}>{type}</Badge>;
  };

  const handleExport = async () => {
    try {
      const response = await apiClient.get('/audit/logs/export', { responseType: 'blob' });
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', 'audit_logs.csv');
      document.body.appendChild(link);
      link.click();
      link.parentNode?.removeChild(link);
    } catch (e) {
      console.error("Export failed", e);
    }
  };

  const verifyRecord = async (eventId: string) => {
    setVerifyingRecordId(eventId);
    try {
      const response = await apiClient.get(`/audit/logs/${eventId}/verify`);
      setRecordVerification((current) => ({ ...current, [eventId]: response.data as AuditRecordVerification }));
    } catch {
      setRecordVerification((current) => ({
        ...current,
        [eventId]: { status: 'error', record_verified: false, scanned_records: 0, missing_records: 0, tampered_records: 0, chain_breaks: 0 },
      }));
    } finally {
      setVerifyingRecordId(null);
    }
  };

  if (error) {
    return <ErrorState title="Audit Engine Offline" description="Cannot connect to the cryptographic ledger." error={error} />;
  }

  const chainIntact = verification.data?.status === 'intact';
  const verificationStatus = verification.isLoading ? 'Verifying...' : chainIntact ? 'Verified' : verification.data?.status === 'tampered' ? 'Tampered' : 'Not verified';

  return (
    <div className="space-y-6 max-w-[1600px] mx-auto pb-10">
      <div className="flex flex-col md:flex-row items-start md:items-end justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-neutral-100 font-sans">Audit & Trust Center</h2>
          <p className="text-sm text-neutral-400 mt-1">Cryptographically verified immutable audit trail.</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button onClick={() => verification.refetch()} variant="outline" className="border-neutral-800 bg-neutral-900/50 hover:bg-neutral-800 text-neutral-300">
            <RefreshCw className="w-4 h-4 mr-2" />
            Verify Integrity
          </Button>
          <Button onClick={handleExport} variant="outline" className="border-neutral-800 bg-neutral-900/50 hover:bg-neutral-800 text-neutral-300">
            <Download className="w-4 h-4 mr-2" />
            Export CSV
          </Button>
        </div>
      </div>

      {/* Audit Integrity Monitoring */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className={`glass-card ${chainIntact ? 'border-emerald-500/20' : 'border-amber-500/20'}`}>
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <p className="text-xs text-neutral-400 font-medium uppercase tracking-wider">Chain Status</p>
              <div className="flex items-center gap-2 mt-1">
                {chainIntact ? <CheckCircle2 className="w-5 h-5 text-emerald-400" /> : <AlertTriangle className="w-5 h-5 text-amber-400" />}
                <span className={`text-xl font-bold ${chainIntact ? 'text-emerald-300' : 'text-amber-300'}`}>{verificationStatus}</span>
              </div>
            </div>
            <div className="text-right">
              <p className="text-xs text-neutral-500">Backend chain proof</p>
              <p className="text-sm font-mono text-neutral-300">{verification.data?.scanned_records ?? 0} scanned</p>
            </div>
          </CardContent>
        </Card>
        
        <Card className="glass-card">
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <p className="text-xs text-neutral-400 font-medium uppercase tracking-wider">Total Blocks</p>
              <div className="flex items-center gap-2 mt-1">
                <Database className="w-5 h-5 text-blue-500" />
                <span className="text-xl font-bold text-neutral-100">{data?.total || 0}</span>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="glass-card">
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <p className="text-xs text-neutral-400 font-medium uppercase tracking-wider">Integrity Findings</p>
              <div className="flex items-center gap-2 mt-1">
                <Key className="w-5 h-5 text-purple-500" />
                <span className="text-xl font-bold text-neutral-100">{verification.data ? `${verification.data.tampered_records}/${verification.data.chain_breaks}` : '0/0'}</span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card className="glass-card flex flex-col min-h-[600px]">
        <div className="p-4 border-b border-white/5 flex gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-neutral-500" />
            <Input
              placeholder="Search cryptographic ledger..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9 bg-black/20 border-neutral-800/50 text-neutral-100 focus-visible:ring-1 focus-visible:ring-neutral-700"
            />
          </div>
          <label className="sr-only" htmlFor="audit-event-type-filter">Filter by event type</label>
          <select
            id="audit-event-type-filter"
            value={eventTypeFilter}
            onChange={(event) => setEventTypeFilter(event.target.value)}
            className="h-10 rounded-md border border-neutral-800/50 bg-black/20 px-3 text-sm text-neutral-300"
          >
            <option value="">All event types</option>
            {eventTypes.map((type) => (
              <option key={type} value={type}>{type}</option>
            ))}
          </select>
          <Button variant="outline" className="border-neutral-800/50 bg-black/20 text-neutral-300 hover:bg-neutral-800" onClick={() => setEventTypeFilter('')}>
            <Filter className="w-4 h-4 mr-2" />
            Clear
          </Button>
        </div>

        <div className="flex-1 overflow-auto">
          {loading ? (
            <div className="p-4"><TableSkeleton columns={6} rows={10} /></div>
          ) : filteredEvents.length === 0 ? (
            <EmptyState 
              title="Ledger Empty" 
              description="No audit events match your search criteria or the ledger is currently empty."
              icon={Database}
            />
          ) : (
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-neutral-900/90 backdrop-blur-md z-10">
                <tr className="border-b border-white/5">
                  <th className="text-left p-4 text-xs font-medium text-neutral-400 uppercase tracking-wider">Timestamp</th>
                  <th className="text-left p-4 text-xs font-medium text-neutral-400 uppercase tracking-wider">Event Type</th>
                  <th className="text-left p-4 text-xs font-medium text-neutral-400 uppercase tracking-wider">Actor / Service</th>
                  <th className="text-left p-4 text-xs font-medium text-neutral-400 uppercase tracking-wider">Action</th>
                  <th className="text-left p-4 text-xs font-medium text-neutral-400 uppercase tracking-wider">Resource</th>
                  <th className="text-right p-4 text-xs font-medium text-neutral-400 uppercase tracking-wider">Hash Link</th>
                </tr>
              </thead>
              <tbody>
                {filteredEvents.map((event) => {
                  const isExpanded = selectedEventId === event.id;
                  return (
                    <React.Fragment key={event.id}>
                      <tr 
                        className={`border-b border-white/5 transition-colors cursor-pointer ${isExpanded ? 'bg-primary/5' : 'hover:bg-white/[0.02]'}`}
                        onClick={() => setSelectedEventId(isExpanded ? null : event.id)}
                      >
                        <td className="p-4 text-neutral-400 whitespace-nowrap">
                          <div className="flex items-center gap-2 font-mono text-[11px]">
                            <Clock className="w-3.5 h-3.5 text-neutral-500" />
                            {new Date(event.created_at).toLocaleString()}
                          </div>
                        </td>
                        <td className="p-4">{getEventTypeBadge(event.event_type)}</td>
                        <td className="p-4 text-neutral-300 font-mono text-xs">
                          {event.user_id ? event.user_id.substring(0, 8) : <span className="text-neutral-500">SYSTEM</span>}
                        </td>
                        <td className="p-4 text-neutral-300 text-xs font-medium tracking-wide uppercase">{event.action}</td>
                        <td className="p-4 text-neutral-400 font-mono text-xs">
                          {event.resource ? `${event.resource}/${event.resource_id?.substring(0, 8) || '*'}` : '—'}
                        </td>
                        <td className="p-4 text-right">
                          <Badge variant="outline" className="font-mono text-[10px] border-emerald-500/20 text-emerald-400 bg-emerald-500/5">
                            <Link2 className="w-3 h-3 mr-1" />
                            {(event.integrity_hash || 'not-returned').substring(0, 12)}
                          </Badge>
                        </td>
                      </tr>
                      <AnimatePresence>
                        {isExpanded && (
                          <motion.tr
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: 'auto' }}
                            exit={{ opacity: 0, height: 0 }}
                            className="bg-black/20 border-b border-white/5"
                          >
                            <td colSpan={6} className="p-0">
                              <div className="p-6 grid grid-cols-1 lg:grid-cols-2 gap-6 overflow-hidden">
                                <div>
                                  <h4 className="text-xs font-semibold text-neutral-400 uppercase tracking-wider mb-3">Event Payload</h4>
                                  <pre className="p-4 rounded-lg bg-[#0a0a0a] border border-neutral-800 font-mono text-[11px] text-neutral-300 overflow-x-auto">
                                    {JSON.stringify(event.metadata || { status: 'recorded' }, null, 2)}
                                  </pre>
                                </div>
                                <div>
                                  <h4 className="text-xs font-semibold text-neutral-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                                    <ShieldCheck className="w-4 h-4 text-emerald-500" />
                                    Hash Chain Explorer
                                  </h4>
                                  <div className="space-y-3">
                                    <div className="p-3 rounded-lg border border-neutral-800 bg-[#0a0a0a]/50">
                                      <p className="text-[10px] text-neutral-500 uppercase tracking-wider mb-1">Previous Block Hash (t-1)</p>
                                      <p className="font-mono text-xs text-neutral-400 break-all">{event.previous_hash || 'genesis or not returned'}</p>
                                    </div>
                                    <div className="flex justify-center text-neutral-600">
                                      <Link2 className="w-4 h-4 rotate-90" />
                                    </div>
                                    <div className="p-3 rounded-lg border border-emerald-500/30 bg-emerald-500/5">
                                      <p className="text-[10px] text-emerald-500/70 uppercase tracking-wider mb-1">Current Block Hash (t)</p>
                                      <p className="font-mono text-xs text-emerald-400 break-all font-semibold">{event.integrity_hash || 'not returned'}</p>
                                    </div>
                                    <div className={`pt-2 flex flex-col gap-2 text-xs ${chainIntact ? 'text-emerald-300' : 'text-amber-300'}`}>
                                      <div className="flex items-center gap-2">
                                        {chainIntact ? <CheckCircle2 className="w-3.5 h-3.5" /> : <AlertTriangle className="w-3.5 h-3.5" />}
                                        Backend verification: {verificationStatus}. Missing records {verification.data?.missing_records ?? 0}, tampered records {verification.data?.tampered_records ?? 0}, chain breaks {verification.data?.chain_breaks ?? 0}.
                                      </div>
                                      <div className="flex flex-wrap items-center gap-2">
                                        <Button size="sm" variant="outline" onClick={() => verifyRecord(event.id)} disabled={verifyingRecordId === event.id}>
                                          <ShieldCheck className="w-3.5 h-3.5 mr-1" />
                                          {verifyingRecordId === event.id ? 'Verifying record...' : 'Verify selected record'}
                                        </Button>
                                        {recordVerification[event.id] && (
                                          <span className={recordVerification[event.id].record_verified ? 'text-emerald-300' : 'text-amber-300'}>
                                            {recordVerification[event.id].record_verified ? 'Selected record verified against hash chain' : `Selected record verification: ${recordVerification[event.id].status}`}
                                          </span>
                                        )}
                                      </div>
                                    </div>
                                  </div>
                                </div>
                              </div>
                            </td>
                          </motion.tr>
                        )}
                      </AnimatePresence>
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </Card>
    </div>
  );
}
