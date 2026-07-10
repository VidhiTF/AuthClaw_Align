"use client";

import { useState } from 'react';
import { Plus, ShieldCheck, Trash2, Edit, ChevronRight, Search, ShieldAlert, Shield } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { usePolicies, useCreatePolicy, useDeletePolicy, useUpdatePolicy, useImportPolicyYaml, useTestPolicyYaml, useValidatePolicyYaml } from '@/hooks/use-data';
import { PolicyForm, type PolicyAction, type PolicySubmitPayload, type RuleType } from '@/components/shared/PolicyForm';
import { CardSkeleton } from '@/components/shared/loaders';
import { EmptyState } from '@/components/shared/states';
import { toast } from 'sonner';
import { motion, AnimatePresence } from 'framer-motion';

interface PolicyRule {
  id: string;
  rule_type: RuleType;
  action: PolicyAction;
  message?: string;
  is_active: boolean;
  conditions: Record<string, unknown>;
  created_at: string;
}

interface Policy {
  id: string;
  name: string;
  description?: string;
  is_active: boolean;
  priority: number;
  created_at: string;
  updated_at: string;
  rules: PolicyRule[];
}

const RULE_TYPE_COLORS: Record<string, string> = {
  pii_block: 'bg-red-500/10 text-red-400 border-red-500/20',
  pii_redact: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
  pii_synthetic: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  content_filter: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
  rate_limit: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
  model_restrict: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  custom: 'bg-neutral-500/10 text-neutral-400 border-neutral-500/20',
};

const ACTION_COLORS: Record<string, string> = {
  block: 'text-red-400',
  warn: 'text-yellow-400',
  allow: 'text-emerald-400',
};

const GUARDRAIL_TAXONOMY = [
  ['Prompt injection', 'Detect and block instruction override attempts.'],
  ['Data disclosure', 'Prevent sensitive data egress and unsafe disclosure.'],
  ['Credential leakage', 'Block or redact tokens, passwords, and API-key markers.'],
  ['Harmful content', 'Route unsafe content to block or review actions.'],
  ['Policy violation', 'Track tenant policy failures and review status.'],
];

const DEFAULT_YAML_POLICY = `version: authclaw.policy/v1
name: Credential leakage block
description: Blocks demo credential markers before provider egress.
enabled: true
priority: 10
rules:
  - type: content_filter
    action: block
    message: Credential marker blocked.
    conditions:
      keywords:
        - token=
  - type: pii_redact
    action: warn
    conditions:
      pii_types: [EMAIL_ADDRESS]
      redaction_mode: MASK
`;

function RuleSummaryBadges({ rules }: { rules: PolicyRule[] }) {
  if (!rules?.length) {
    return <span className="text-xs text-neutral-600 italic">No enforced rules</span>;
  }
  return (
    <div className="flex flex-wrap gap-1 mt-2">
      {rules.map((rule) => (
        <span
          key={rule.id}
          className={`inline-flex items-center gap-1.5 text-[10px] px-2 py-0.5 rounded-full border font-medium ${RULE_TYPE_COLORS[rule.rule_type] ?? RULE_TYPE_COLORS.custom}`}
        >
          <span className={`font-bold ${ACTION_COLORS[rule.action] ?? ''}`}>
            {rule.action.toUpperCase()}
          </span>
          <span className="opacity-80">•</span>
          {rule.rule_type.replace('_', ' ')}
        </span>
      ))}
    </div>
  );
}

// ─── Modal wrapper ─────────────────────────────────────────────────────────────

interface ModalProps {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
}

function Modal({ title, onClose, children }: ModalProps) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <motion.div 
        initial={{ opacity: 0 }} 
        animate={{ opacity: 1 }} 
        exit={{ opacity: 0 }}
        className="absolute inset-0 bg-black/80 backdrop-blur-sm"
        onClick={onClose}
      />
      <motion.div 
        initial={{ opacity: 0, scale: 0.95, y: 20 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.95, y: 20 }}
        className="bg-[#0a0a0a] border border-white/10 rounded-2xl w-full max-w-2xl max-h-[90vh] flex flex-col shadow-2xl relative z-10 overflow-hidden"
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-5 border-b border-white/5 bg-white/[0.02] shrink-0">
          <h2 className="text-lg font-bold text-neutral-100 flex items-center gap-2">
            <Shield className="w-5 h-5 text-blue-400" />
            {title}
          </h2>
          <button
            onClick={onClose}
            className="text-neutral-500 hover:text-white transition-colors text-2xl leading-none w-8 h-8 flex items-center justify-center rounded-full hover:bg-white/10"
          >
            ×
          </button>
        </div>
        {/* Body */}
        <div className="overflow-y-auto flex-1 px-6 py-6 bg-transparent">{children}</div>
      </motion.div>
    </div>
  );
}

// ─── Main Page ─────────────────────────────────────────────────────────────────

export default function PoliciesPage() {
  const { data: policies = [], isLoading: loading } = usePolicies();
  const createMutation = useCreatePolicy();
  const updateMutation = useUpdatePolicy();
  const deleteMutation = useDeletePolicy();
  const validateYamlMutation = useValidatePolicyYaml();
  const testYamlMutation = useTestPolicyYaml();
  const importYamlMutation = useImportPolicyYaml();

  const [showCreate, setShowCreate] = useState(false);
  const [editingPolicy, setEditingPolicy] = useState<Policy | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [yamlDraft, setYamlDraft] = useState(DEFAULT_YAML_POLICY);
  const [sampleText, setSampleText] = useState('A demo token=sample should be blocked.');
  const [validationResult, setValidationResult] = useState<Record<string, unknown> | null>(null);
  const [policyTestResult, setPolicyTestResult] = useState<Record<string, unknown> | null>(null);

  // ─── Handlers ───────────────────────────────────────────────────────────────

  const handleCreate = async (payload: PolicySubmitPayload) => {
    try {
      await createMutation.mutateAsync(payload);
      toast.success(`Policy "${payload.name}" created with ${payload.rules.length} rule(s).`);
      setShowCreate(false);
    } catch (err: unknown) {
      const apiError = err as { response?: { data?: { detail?: string } } };
      toast.error(apiError.response?.data?.detail || 'Failed to create policy');
    }
  };

  const handleEdit = async (payload: PolicySubmitPayload) => {
    if (!editingPolicy) return;
    try {
      await updateMutation.mutateAsync({ id: editingPolicy.id, data: payload });
      toast.success(`Policy "${payload.name}" updated.`);
      setEditingPolicy(null);
    } catch (err: unknown) {
      const apiError = err as { response?: { data?: { detail?: string } } };
      toast.error(apiError.response?.data?.detail || 'Failed to update policy');
    }
  };

  const handleToggleActive = async (policy: Policy) => {
    const action = policy.is_active ? 'disable' : 'enable';
    if (!window.confirm(`Confirm ${action} policy "${policy.name}"? This changes gateway enforcement behavior.`)) return;
    try {
      await updateMutation.mutateAsync({
        id: policy.id,
        data: { is_active: !policy.is_active },
      });
      toast.success(`Policy ${policy.is_active ? 'disabled' : 'enabled'}`);
    } catch {
      toast.error('Failed to update policy');
    }
  };

  const handleDelete = async (id: string, name: string) => {
    if (!window.confirm(`Delete policy "${name}"? This cannot be undone.`)) return;
    try {
      await deleteMutation.mutateAsync(id);
      toast.success('Policy deleted');
      if (expandedId === id) setExpandedId(null);
    } catch {
      toast.error('Failed to delete policy');
    }
  };

  const handleValidateYaml = async () => {
    try {
      const result = await validateYamlMutation.mutateAsync(yamlDraft);
      setValidationResult(result);
      if (result.valid) {
        toast.success('Policy YAML is valid');
      } else {
        toast.error('Policy YAML needs review');
      }
    } catch {
      toast.error('Failed to validate policy YAML');
    }
  };

  const handleTestYaml = async () => {
    try {
      const result = await testYamlMutation.mutateAsync({ yamlSource: yamlDraft, sampleText });
      setPolicyTestResult(result);
      toast.success(result.blocked ? 'Sample blocked by policy' : 'Sample allowed by policy');
    } catch {
      toast.error('Failed to test policy YAML');
    }
  };

  const handleImportYaml = async () => {
    if (!window.confirm('Save this validated YAML policy?')) return;
    try {
      await importYamlMutation.mutateAsync(yamlDraft);
      toast.success('YAML policy imported');
    } catch (err: unknown) {
      const apiError = err as { response?: { data?: { detail?: string | { message?: string } } } };
      const detail = apiError.response?.data?.detail;
      toast.error(typeof detail === 'string' ? detail : detail?.message || 'Failed to import YAML policy');
    }
  };

  const filteredPolicies = policies.filter((p: Policy) => 
    p.name.toLowerCase().includes(searchQuery.toLowerCase()) || 
    (p.description && p.description.toLowerCase().includes(searchQuery.toLowerCase()))
  );

  const activeCount = policies.filter((p: Policy) => p.is_active).length;

  // ─── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-6 max-w-[1600px] mx-auto pb-10">
      {/* Page header */}
      <div className="flex flex-col md:flex-row items-start md:items-end justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-neutral-100 font-sans">Policy Governance</h2>
          <p className="text-sm text-neutral-400 mt-1">Define and enforce security guardrails across all AI model traffic.</p>
        </div>
        <Button
          onClick={() => setShowCreate(true)}
          className="bg-blue-600 hover:bg-blue-500 text-white font-medium px-5"
          disabled={createMutation.isPending}
        >
          <Plus className="w-4 h-4 mr-2" />
          Create Policy
        </Button>
      </div>

      <div className="flex items-center justify-between bg-black/20 border border-white/5 rounded-xl p-2 gap-4">
        <div className="flex-1 relative">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-neutral-500" />
          <input 
            type="text" 
            placeholder="Search policies..." 
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-transparent border-none focus:ring-0 text-sm text-neutral-200 placeholder:text-neutral-600 pl-10 py-2"
          />
        </div>
        <div className="px-4 border-l border-white/10 hidden sm:flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          <span className="text-xs font-medium text-neutral-300"><span className="text-emerald-400">{activeCount}</span> Active</span>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        {GUARDRAIL_TAXONOMY.map(([title, description]) => (
          <Card key={title} className="glass-card">
            <CardContent className="p-4">
              <div className="flex items-center gap-2 text-sm font-semibold text-neutral-100">
                <Shield className="w-4 h-4 text-blue-400" />
                {title}
              </div>
              <p className="mt-2 text-xs leading-5 text-neutral-400">{description}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <Card className="glass-card border-blue-500/20">
        <CardContent className="p-4">
          <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
            <div>
              <p className="text-sm font-semibold text-neutral-100">Validation status</p>
              <p className="text-xs text-neutral-400 mt-1">Policies are validated by the backend when saved. Enforcement changes require explicit confirmation; no unsafe auto-apply is performed by this console.</p>
            </div>
            <Badge variant="outline" className="bg-blue-500/10 text-blue-300 border-blue-500/20">Backend validated on save</Badge>
          </div>
        </CardContent>
      </Card>

      <Card className="glass-card border-purple-500/20">
        <CardContent className="p-4 space-y-4">
          <div className="flex flex-col gap-2 md:flex-row md:items-start md:justify-between">
            <div>
              <p className="text-sm font-semibold text-neutral-100">YAML policy-as-code</p>
              <p className="text-xs text-neutral-400 mt-1">Validate and test policy YAML before saving. Runtime uses the backend policy engine with an OPA-compatible adapter seam.</p>
            </div>
            <Badge variant="outline" className="bg-purple-500/10 text-purple-300 border-purple-500/20">OPA adapter seam</Badge>
          </div>
          <div className="grid lg:grid-cols-[1.2fr_0.8fr] gap-4">
            <textarea
              value={yamlDraft}
              onChange={(event) => setYamlDraft(event.target.value)}
              spellCheck={false}
              className="min-h-72 w-full resize-y rounded-lg border border-white/10 bg-black/40 p-3 font-mono text-xs leading-5 text-neutral-200 outline-none focus:ring-2 focus:ring-purple-500/40"
              aria-label="YAML policy editor"
            />
            <div className="space-y-3">
              <textarea
                value={sampleText}
                onChange={(event) => setSampleText(event.target.value)}
                className="min-h-24 w-full resize-y rounded-lg border border-white/10 bg-black/40 p-3 text-sm text-neutral-200 outline-none focus:ring-2 focus:ring-purple-500/40"
                aria-label="Policy test sample"
                placeholder="Sample text for policy test"
              />
              <div className="flex flex-wrap gap-2">
                <Button type="button" variant="outline" onClick={handleValidateYaml} disabled={validateYamlMutation.isPending}>Validate</Button>
                <Button type="button" variant="outline" onClick={handleTestYaml} disabled={testYamlMutation.isPending}>Test Prompt</Button>
                <Button type="button" onClick={handleImportYaml} disabled={importYamlMutation.isPending} className="bg-purple-600 hover:bg-purple-500 text-white">Save YAML</Button>
              </div>
              <div className="rounded-lg border border-white/10 bg-black/30 p-3 text-xs text-neutral-300 min-h-28">
                <p className="font-semibold text-neutral-100 mb-2">Validation result</p>
                {validationResult ? (
                  <pre className="whitespace-pre-wrap font-mono text-[11px] text-neutral-400">{JSON.stringify(validationResult, null, 2)}</pre>
                ) : (
                  <p className="text-neutral-500">No validation run yet.</p>
                )}
              </div>
              <div className="rounded-lg border border-white/10 bg-black/30 p-3 text-xs text-neutral-300 min-h-24">
                <p className="font-semibold text-neutral-100 mb-2">Test result</p>
                {policyTestResult ? (
                  <pre className="whitespace-pre-wrap font-mono text-[11px] text-neutral-400">{JSON.stringify(policyTestResult, null, 2)}</pre>
                ) : (
                  <p className="text-neutral-500">No test run yet.</p>
                )}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Policy list */}
      {loading ? (
        <div className="grid gap-4">
          <CardSkeleton />
          <CardSkeleton />
          <CardSkeleton />
        </div>
      ) : policies.length === 0 ? (
        <EmptyState 
          title="No Security Policies" 
          description="Create your first policy to enforce PII redaction, content filtering, and rate limits."
          icon={ShieldAlert}
          action={{
            label: "Create Policy",
            onClick: () => setShowCreate(true)
          }}
        />
      ) : filteredPolicies.length === 0 ? (
        <EmptyState 
          title="No Policies Found" 
          description="No policies match your current search criteria."
          icon={Search}
        />
      ) : (
        <div className="grid gap-4">
          <AnimatePresence>
            {(filteredPolicies as Policy[]).map((policy, idx) => {
              const isExpanded = expandedId === policy.id;
              return (
                <motion.div 
                  key={policy.id}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: idx * 0.05 }}
                  layout
                >
                  <Card
                    className={`glass-card overflow-hidden transition-all duration-300 ${
                      isExpanded ? 'border-blue-500/40 shadow-[0_0_15px_rgba(59,130,246,0.1)]' : 'border-white/5 hover:border-white/10'
                    }`}
                  >
                    <CardContent className="p-0">
                      {/* Policy row */}
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between p-5 gap-4">
                        <div className="flex items-start sm:items-center gap-4 min-w-0">
                          <div
                            className={`shrink-0 w-10 h-10 rounded-xl flex items-center justify-center border shadow-inner ${
                              policy.is_active 
                                ? 'bg-blue-500/10 border-blue-500/20 text-blue-400' 
                                : 'bg-neutral-800 border-neutral-700 text-neutral-500'
                            }`}
                          >
                            <ShieldCheck className="w-5 h-5" />
                          </div>
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center gap-3 flex-wrap">
                              <h3 className="font-semibold text-neutral-100 text-base">
                                {policy.name}
                              </h3>
                              <Badge
                                variant="outline"
                                className={
                                  policy.is_active
                                    ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20 uppercase tracking-wider text-[10px]'
                                    : 'bg-neutral-500/10 text-neutral-400 border-neutral-700 uppercase tracking-wider text-[10px]'
                                }
                              >
                                {policy.is_active ? 'Active' : 'Disabled'}
                              </Badge>
                              {policy.priority > 0 && (
                                <Badge variant="outline" className="bg-white/5 border-white/10 text-neutral-400 text-[10px] font-mono">
                                  PRIORITY: {policy.priority}
                                </Badge>
                              )}
                            </div>
                            {policy.description && (
                              <p className="text-sm text-neutral-400 mt-1 max-w-2xl line-clamp-1">
                                {policy.description}
                              </p>
                            )}
                            <RuleSummaryBadges rules={policy.rules} />
                          </div>
                        </div>

                        {/* Actions */}
                        <div className="flex items-center gap-2 shrink-0 sm:ml-4 bg-black/20 p-1.5 rounded-lg border border-white/5">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleToggleActive(policy)}
                            disabled={updateMutation.isPending}
                            className={`text-xs h-8 ${policy.is_active ? 'text-amber-400 hover:text-amber-300 hover:bg-amber-400/10' : 'text-emerald-400 hover:text-emerald-300 hover:bg-emerald-400/10'}`}
                          >
                            {policy.is_active ? 'Disable' : 'Enable'}
                          </Button>
                          <div className="w-px h-4 bg-white/10 mx-1"></div>
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => setEditingPolicy(policy)}
                            className="h-8 w-8 text-neutral-400 hover:text-blue-400 hover:bg-blue-400/10"
                            title="Edit policy"
                          >
                            <Edit className="w-4 h-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => handleDelete(policy.id, policy.name)}
                            disabled={deleteMutation.isPending}
                            className="h-8 w-8 text-neutral-400 hover:text-red-400 hover:bg-red-400/10"
                            title="Delete policy"
                          >
                            <Trash2 className="w-4 h-4" />
                          </Button>
                          <div className="w-px h-4 bg-white/10 mx-1"></div>
                          <button
                            onClick={() => setExpandedId(isExpanded ? null : policy.id)}
                            className={`h-8 w-8 flex items-center justify-center text-neutral-500 hover:text-white transition-colors rounded ${isExpanded ? 'bg-white/10 text-white' : ''}`}
                            title={isExpanded ? 'Collapse' : 'View details'}
                          >
                            <ChevronRight
                              className={`w-4 h-4 transition-transform ${isExpanded ? 'rotate-90' : ''}`}
                            />
                          </button>
                        </div>
                      </div>

                      {/* Expanded: rule details */}
                      <AnimatePresence>
                        {isExpanded && (
                          <motion.div 
                            initial={{ height: 0, opacity: 0 }}
                            animate={{ height: 'auto', opacity: 1 }}
                            exit={{ height: 0, opacity: 0 }}
                            className="overflow-hidden"
                          >
                            <div className="border-t border-white/5 p-5 bg-black/40">
                              {policy.rules.length === 0 ? (
                                <p className="text-sm text-neutral-500 italic flex items-center justify-center py-6 bg-white/[0.02] rounded-xl border border-white/5 border-dashed">
                                  This policy has no active rules. Click Edit to define governance controls.
                                </p>
                              ) : (
                                <div className="space-y-3">
                                  <p className="text-xs text-neutral-500 font-medium uppercase tracking-wider mb-2">
                                    Enforced Rules ({policy.rules.length})
                                  </p>
                                  {policy.rules.map((rule, idx) => (
                                    <div
                                      key={rule.id}
                                      className="flex items-start gap-4 bg-white/[0.02] border border-white/5 rounded-xl p-4 hover:bg-white/[0.04] transition-colors"
                                    >
                                      <div className="w-6 h-6 rounded bg-black/50 border border-white/10 flex items-center justify-center text-xs text-neutral-500 font-mono shrink-0">
                                        {idx + 1}
                                      </div>
                                      <div className="flex-1 min-w-0 space-y-2">
                                        <div className="flex items-center gap-2 flex-wrap">
                                          <Badge variant="outline" className={`bg-black/40 font-mono text-[10px] uppercase border-white/10 ${ACTION_COLORS[rule.action] ?? ''}`}>
                                            ACT: {rule.action}
                                          </Badge>
                                          <Badge variant="outline" className={`font-mono text-[10px] uppercase ${RULE_TYPE_COLORS[rule.rule_type] ?? RULE_TYPE_COLORS.custom}`}>
                                            {rule.rule_type}
                                          </Badge>
                                          {!rule.is_active && (
                                            <Badge variant="outline" className="bg-transparent border-neutral-700 text-neutral-500 text-[10px] uppercase">
                                              Inactive
                                            </Badge>
                                          )}
                                        </div>
                                        {rule.message && (
                                          <p className="text-sm text-neutral-300 font-medium">{rule.message}</p>
                                        )}
                                        {Object.keys(rule.conditions).length > 0 && (
                                          <div className="bg-[#0a0a0a] rounded-lg border border-white/5 p-3 overflow-x-auto mt-2">
                                            <pre className="text-[11px] text-neutral-400 font-mono">
                                              {JSON.stringify(rule.conditions, null, 2)}
                                            </pre>
                                          </div>
                                        )}
                                      </div>
                                    </div>
                                  ))}
                                </div>
                              )}
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </CardContent>
                  </Card>
                </motion.div>
              );
            })}
          </AnimatePresence>
        </div>
      )}

      {/* Create Modal */}
      <AnimatePresence>
        {showCreate && (
          <Modal title="Create Security Policy" onClose={() => setShowCreate(false)}>
            <PolicyForm
              mode="create"
              onSubmit={handleCreate}
              onCancel={() => setShowCreate(false)}
              isPending={createMutation.isPending}
            />
          </Modal>
        )}
      </AnimatePresence>

      {/* Edit Modal */}
      <AnimatePresence>
        {editingPolicy && (
          <Modal
            title={`Edit Policy: ${editingPolicy.name}`}
            onClose={() => setEditingPolicy(null)}
          >
            <PolicyForm
              mode="edit"
              initialData={editingPolicy}
              onSubmit={handleEdit}
              onCancel={() => setEditingPolicy(null)}
              isPending={updateMutation.isPending}
            />
          </Modal>
        )}
      </AnimatePresence>
    </div>
  );
}
