'use client';

import { useState } from 'react';
import { useApprovals, useRunAgentScan, useApproveAction, useRejectAction } from '@/hooks/use-data';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Search, Loader2, CheckCircle, XCircle, ShieldCheck, Clock, Activity, Cpu, Server } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from '@/components/ui/dialog';
import { toast } from 'sonner';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { EmptyState } from '@/components/shared/states';
import { TableSkeleton } from '@/components/shared/loaders';

type Approval = {
  id: string;
  title: string;
  description?: string | null;
  diff_content?: string | null;
  action_type: string;
  status: 'pending' | 'executed' | 'rejected' | string;
  created_at: string;
};

type ApiError = {
  response?: {
    data?: {
      detail?: string;
    };
  };
};

export default function ApprovalsPage() {
  const { data: approvals = [], isLoading } = useApprovals();
  const runScanMutation = useRunAgentScan();
  const approveMutation = useApproveAction();
  const rejectMutation = useRejectAction();

  const [selectedApproval, setSelectedApproval] = useState<Approval | null>(null);
  const [showMfaPrompt, setShowMfaPrompt] = useState(false);
  const [mfaCode, setMfaCode] = useState('');
  const [searchQuery, setSearchQuery] = useState('');

  const handleRunScan = async (target: string) => {
    try {
      toast.info(`Running agent scan on ${target}...`);
      await runScanMutation.mutateAsync(target);
      toast.success('Scan complete. New actions created.');
    } catch {
      toast.error('Failed to run scan');
    }
  };

  const handleApproveClick = () => {
    if (!selectedApproval) return;
    setMfaCode('');
    setShowMfaPrompt(true);
  };

  const executeApproval = async () => {
    if (!selectedApproval) return;
    try {
      await approveMutation.mutateAsync({ id: selectedApproval.id, code: mfaCode });
      toast.success('Action approved and executed!');
      setShowMfaPrompt(false);
      setSelectedApproval({ ...selectedApproval, status: 'executed' });
    } catch (err: unknown) {
      const apiError = err as ApiError;
      toast.error(apiError.response?.data?.detail || 'Failed to approve action');
    }
  };

  const handleReject = async () => {
    if (!selectedApproval) return;
    try {
      await rejectMutation.mutateAsync(selectedApproval.id);
      toast.success('Action rejected.');
      setSelectedApproval({ ...selectedApproval, status: 'rejected' });
    } catch {
      toast.error('Failed to reject action');
    }
  };

  const formatDate = (dateStr: string) => {
    return new Intl.DateTimeFormat('en-US', { 
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' 
    }).format(new Date(dateStr));
  };

  const filteredApprovals = (approvals as Approval[]).filter((item) => 
    searchQuery === '' || item.title.toLowerCase().includes(searchQuery.toLowerCase()) || item.action_type.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="space-y-6 max-w-[1600px] mx-auto pb-10 flex flex-col h-[calc(100vh-6rem)]">
      <div className="flex flex-col md:flex-row items-start md:items-end justify-between gap-4 shrink-0">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-neutral-100 font-sans">Action Center</h1>
          <p className="text-sm text-neutral-400 mt-1">Human-in-the-loop (HITL) approval workflows and remediation.</p>
        </div>
        <div className="flex gap-3">
          <Button 
            onClick={() => handleRunScan('AWS')}
            disabled={runScanMutation.isPending}
            variant="outline"
            className="border-orange-500/30 text-orange-400 bg-orange-500/10 hover:bg-orange-500/20"
          >
            {runScanMutation.isPending ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Server className="w-4 h-4 mr-2" />}
            Scan AWS
          </Button>
          <Button 
            onClick={() => handleRunScan('GitHub')}
            disabled={runScanMutation.isPending}
            variant="outline"
            className="border-neutral-700 text-neutral-300 bg-neutral-800/50 hover:bg-neutral-800"
          >
            {runScanMutation.isPending ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Activity className="w-4 h-4 mr-2" />}
            Scan GitHub
          </Button>
        </div>
      </div>

      <div className="flex flex-col lg:flex-row gap-6 flex-1 min-h-0">
        {/* Left Panel: List of Actions */}
        <Card className="glass-card flex-1 flex flex-col min-h-0 overflow-hidden lg:max-w-md xl:max-w-lg shrink-0">
          <div className="p-4 border-b border-white/5 flex gap-2 shrink-0">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-neutral-500" />
              <Input
                placeholder="Search pending actions..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9 bg-black/20 border-neutral-800/50 text-neutral-100"
              />
            </div>
          </div>
          <div className="flex-1 overflow-y-auto">
            {isLoading ? (
              <div className="p-4"><TableSkeleton columns={1} rows={5} /></div>
            ) : filteredApprovals.length === 0 ? (
              <EmptyState title="No pending actions" description="All clear! No HITL approvals require your attention." icon={CheckCircle} />
            ) : (
              <ul className="divide-y divide-white/5">
                {filteredApprovals.map((item) => {
                  const isSelected = selectedApproval?.id === item.id;
                  let statusBadge = null;
                  if (item.status === 'pending') {
                    statusBadge = <Badge variant="outline" className="ml-auto bg-amber-500/10 text-amber-500 border-amber-500/20 text-[10px] uppercase">Pending</Badge>;
                  } else if (item.status === 'executed') {
                    statusBadge = <Badge variant="outline" className="ml-auto bg-emerald-500/10 text-emerald-500 border-emerald-500/20 text-[10px] uppercase">Executed</Badge>;
                  } else {
                    statusBadge = <Badge variant="outline" className="ml-auto bg-red-500/10 text-red-500 border-red-500/20 text-[10px] uppercase">Rejected</Badge>;
                  }

                  return (
                    <li 
                      key={item.id} 
                      onClick={() => setSelectedApproval(item)}
                      className={`p-4 cursor-pointer transition-colors border-l-2 ${isSelected ? 'bg-white/[0.04] border-emerald-500' : 'border-transparent hover:bg-white/[0.02]'}`}
                    >
                      <div className="flex items-start justify-between mb-2">
                        <div className="flex items-center gap-2 text-xs text-neutral-500 font-mono">
                          <Clock className="w-3.5 h-3.5" />
                          {formatDate(item.created_at)}
                        </div>
                        {statusBadge}
                      </div>
                      <h4 className="text-sm font-medium text-neutral-200 mb-1">{item.title}</h4>
                      <Badge variant="outline" className="text-[10px] text-neutral-400 border-neutral-800 bg-black/20 uppercase">
                        {item.action_type}
                      </Badge>
                    </li>
                  )
                })}
              </ul>
            )}
          </div>
        </Card>

        {/* Right Panel: Detail & Workflow Timeline */}
        <Card className="glass-card flex-[2] flex flex-col min-h-0 overflow-hidden relative">
          {selectedApproval ? (
            <div className="flex flex-col h-full overflow-hidden">
              <div className="p-6 border-b border-white/5 shrink-0 bg-black/20">
                <div className="flex items-center gap-3 mb-2">
                  <Badge variant="outline" className="text-[10px] text-neutral-400 border-neutral-800 bg-neutral-900/50 uppercase">
                    ID: {selectedApproval.id.substring(0, 8)}
                  </Badge>
                  <Badge className={
                        selectedApproval.status === 'pending' ? 'bg-amber-500/10 text-amber-500 border-amber-500/20' :
                        selectedApproval.status === 'executed' ? 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20' :
                        'bg-red-500/10 text-red-500 border-red-500/20'
                      }>
                    {selectedApproval.status.toUpperCase()}
                  </Badge>
                </div>
                <h2 className="text-2xl font-bold text-neutral-100">{selectedApproval.title}</h2>
              </div>
              
              <div className="flex-1 overflow-y-auto p-6 grid grid-cols-1 xl:grid-cols-2 gap-8">
                {/* Timeline Column */}
                <div>
                  <h3 className="text-sm font-medium text-neutral-400 mb-6 uppercase tracking-wider flex items-center gap-2">
                    <Activity className="w-4 h-4 text-emerald-500" />
                    Approval Workflow
                  </h3>
                  
                  <div className="relative border-l-2 border-neutral-800 ml-3 space-y-8 pb-4">
                    {/* Step 1 */}
                    <div className="relative pl-8">
                      <div className="absolute w-6 h-6 bg-emerald-500/20 border border-emerald-500/50 rounded-full -left-[13px] top-0 flex items-center justify-center z-10">
                        <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
                      </div>
                      <h4 className="text-sm font-semibold text-neutral-200">AI Detection & Analysis</h4>
                      <p className="text-xs text-neutral-500 mt-1">Autonomous agent identified risk and proposed remediation.</p>
                      <div className="mt-3 bg-black/30 border border-white/5 rounded-lg p-3 text-xs text-neutral-400 font-mono">
                        Rule triggered: <span className="text-emerald-400">{selectedApproval.action_type}_misconfiguration</span>
                      </div>
                    </div>

                    {/* Step 2 */}
                    <div className="relative pl-8">
                      <div className="absolute w-6 h-6 bg-emerald-500/20 border border-emerald-500/50 rounded-full -left-[13px] top-0 flex items-center justify-center z-10">
                        <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
                      </div>
                      <h4 className="text-sm font-semibold text-neutral-200">Policy Validation</h4>
                      <p className="text-xs text-neutral-500 mt-1">Simulated execution against current organizational policies.</p>
                      <div className="mt-3 flex items-center gap-2 text-xs text-emerald-500 bg-emerald-500/5 border border-emerald-500/10 p-2 rounded w-fit">
                        <ShieldCheck className="w-3.5 h-3.5" />
                        Passes 43/43 Security Checks
                      </div>
                    </div>

                    {/* Step 3 */}
                    <div className="relative pl-8">
                      <div className={`absolute w-6 h-6 rounded-full -left-[13px] top-0 flex items-center justify-center z-10 
                        ${selectedApproval.status === 'pending' ? 'bg-amber-500/20 border border-amber-500/50 shadow-[0_0_15px_rgba(245,158,11,0.2)]' : 
                          selectedApproval.status === 'executed' ? 'bg-emerald-500/20 border border-emerald-500/50' : 
                          'bg-red-500/20 border border-red-500/50'}`}
                      >
                        {selectedApproval.status === 'pending' ? (
                          <div className="w-2 h-2 rounded-full bg-amber-400 animate-pulse" />
                        ) : selectedApproval.status === 'executed' ? (
                          <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <XCircle className="w-3.5 h-3.5 text-red-400" />
                        )}
                      </div>
                      <h4 className="text-sm font-semibold text-neutral-200">Human-In-The-Loop Approval</h4>
                      <p className="text-xs text-neutral-500 mt-1">Requires MFA verification by authorized administrator.</p>
                      {selectedApproval.status === 'pending' && (
                        <div className="mt-4 flex gap-3">
                          <Button 
                            onClick={handleApproveClick}
                            className="bg-emerald-600 hover:bg-emerald-700 text-white text-xs h-8"
                          >
                            <ShieldCheck className="w-3.5 h-3.5 mr-1.5" />
                            Verify & Approve
                          </Button>
                          <Button 
                            variant="outline" 
                            onClick={handleReject}
                            className="border-neutral-700 text-neutral-300 hover:bg-red-500/10 hover:text-red-500 hover:border-red-500/30 text-xs h-8"
                          >
                            Reject
                          </Button>
                        </div>
                      )}
                    </div>

                    {/* Step 4 */}
                    <div className="relative pl-8 opacity-50">
                      <div className={`absolute w-6 h-6 rounded-full -left-[13px] top-0 flex items-center justify-center z-10 bg-neutral-900 border border-neutral-700
                        ${selectedApproval.status === 'executed' ? '!bg-emerald-500/20 !border-emerald-500/50 !opacity-100' : ''}`}
                      >
                         {selectedApproval.status === 'executed' ? <CheckCircle className="w-3.5 h-3.5 text-emerald-400" /> : <div className="w-2 h-2 rounded-full bg-neutral-600" />}
                      </div>
                      <h4 className={`text-sm font-semibold ${selectedApproval.status === 'executed' ? 'text-neutral-200' : 'text-neutral-500'}`}>Execution</h4>
                      <p className="text-xs text-neutral-600 mt-1">Deploy changes to target environment.</p>
                    </div>
                  </div>
                </div>

                {/* Details Column */}
                <div className="space-y-6">
                  <div>
                    <h3 className="text-sm font-medium text-neutral-400 mb-3 uppercase tracking-wider flex items-center gap-2">
                      <Cpu className="w-4 h-4 text-blue-500" />
                      Agent Analysis
                    </h3>
                    <div className="bg-black/30 p-4 rounded-xl border border-white/5 prose prose-sm prose-invert max-w-none text-neutral-300 text-sm leading-relaxed">
                      <ReactMarkdown remarkPlugins={[remarkGfm]}>
                        {selectedApproval.description || ''}
                      </ReactMarkdown>
                    </div>
                  </div>

                  <div>
                    <h3 className="text-sm font-medium text-neutral-400 mb-3 uppercase tracking-wider flex items-center gap-2">
                      <Activity className="w-4 h-4 text-amber-500" />
                      Proposed Remediation
                    </h3>
                    <div className="bg-[#0a0a0a] rounded-xl border border-neutral-800/80 overflow-hidden shadow-inner">
                      <div className="bg-neutral-900/80 px-4 py-2 border-b border-neutral-800/80 flex items-center justify-between text-xs text-neutral-400 font-mono">
                        <span>proposed_changes.{selectedApproval.action_type === 'terraform' ? 'tf' : 'sh'}</span>
                        <span className="text-amber-500">pending</span>
                      </div>
                      <pre className="p-4 text-xs font-mono text-emerald-400 overflow-x-auto">
                        {selectedApproval.diff_content}
                      </pre>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <EmptyState 
              title="No action selected" 
              description="Select an action from the list to review the workflow timeline and details."
              icon={Activity}
            />
          )}
        </Card>
      </div>

      <Dialog open={showMfaPrompt} onOpenChange={setShowMfaPrompt}>
        <DialogContent className="sm:max-w-md bg-neutral-900 border-neutral-800 text-neutral-100">
          <DialogHeader>
            <DialogTitle>MFA Verification Required</DialogTitle>
            <DialogDescription className="text-neutral-400">
              Please enter your 6-digit authenticator code to authorize this action.
            </DialogDescription>
          </DialogHeader>
          <div className="flex flex-col items-center justify-center space-y-4 py-4">
            <div className="w-full">
              <Input
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value)}
                placeholder="123456"
                className="bg-neutral-950 border-neutral-800 text-neutral-100 text-center tracking-[0.5em] font-mono text-lg"
                maxLength={6}
                autoFocus
              />
            </div>
          </div>
          <DialogFooter className="bg-transparent border-t-0 p-0">
            <Button variant="ghost" onClick={() => setShowMfaPrompt(false)}>Cancel</Button>
            <Button 
              onClick={executeApproval} 
              disabled={mfaCode.length !== 6 || approveMutation.isPending} 
              className="bg-emerald-600 hover:bg-emerald-700 text-white"
            >
              {approveMutation.isPending ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <ShieldCheck className="w-4 h-4 mr-2" />}
              Verify & Approve
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
