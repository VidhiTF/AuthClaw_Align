"use client";

import { useState } from 'react';
import { Plus, Trash2, ChevronDown, ChevronUp, Code } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent } from '@/components/ui/card';

// ─── Types ────────────────────────────────────────────────────────────────────

export type RuleType =
  | 'pii_block'
  | 'pii_redact'
  | 'pii_synthetic'
  | 'content_filter'
  | 'rate_limit'
  | 'model_restrict'
  | 'custom';

export type PolicyAction = 'allow' | 'warn' | 'block';

export interface PolicyRuleForm {
  rule_type: RuleType;
  action: PolicyAction;
  message: string;
  is_active: boolean;
  /** Raw JSON string shown in the advanced editor */
  conditionsRaw: string;
  /** Parsed conditions object built from the visual helpers */
  conditions: Record<string, unknown>;
  /** Whether the user is viewing the raw JSON panel */
  showRaw: boolean;
  /** Whether this rule card is expanded */
  expanded: boolean;
}

export interface PolicyFormData {
  name: string;
  description: string;
  is_active: boolean;
  priority: number;
  rules: PolicyRuleForm[];
}

export interface ApiPolicyRule {
  rule_type: RuleType;
  action: PolicyAction;
  message?: string | null;
  is_active?: boolean;
  conditions?: Record<string, unknown>;
}

export interface ApiPolicyData {
  name?: string;
  description?: string | null;
  is_active?: boolean;
  priority?: number;
  rules?: ApiPolicyRule[];
}

export interface PolicySubmitPayload {
  [key: string]: unknown;
  name: string;
  description: string | null;
  is_active: boolean;
  priority: number;
  rules: Array<{
    rule_type: RuleType;
    action: PolicyAction;
    message: string | null;
    is_active: boolean;
    conditions: Record<string, unknown>;
  }>;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const RULE_TYPE_LABELS: Record<RuleType, string> = {
  pii_block: 'PII Block',
  pii_redact: 'PII Redact',
  pii_synthetic: 'PII Synthetic',
  content_filter: 'Content Filter',
  rate_limit: 'Rate Limit',
  model_restrict: 'Model Restrict',
  custom: 'Custom',
};

const ACTION_LABELS: Record<PolicyAction, string> = {
  allow: 'Allow',
  warn: 'Warn',
  block: 'Block',
};

const ACTION_COLORS: Record<PolicyAction, string> = {
  allow: 'text-green-400',
  warn: 'text-yellow-400',
  block: 'text-red-400',
};

function buildConditionsFromVisual(
  ruleType: RuleType,
  visual: Record<string, string>,
): Record<string, unknown> {
  switch (ruleType) {
    case 'pii_block':
    case 'pii_redact':
    case 'pii_synthetic':
      return {
        pii_types: visual.pii_types
          ? visual.pii_types.split(',').map((s) => s.trim()).filter(Boolean)
          : [],
      };
    case 'rate_limit':
      return {
        max_requests: visual.max_requests ? parseInt(visual.max_requests, 10) : 100,
        window_seconds: visual.window_seconds ? parseInt(visual.window_seconds, 10) : 60,
      };
    case 'model_restrict':
      return {
        allowed_models: visual.allowed_models
          ? visual.allowed_models.split(',').map((s) => s.trim()).filter(Boolean)
          : [],
      };
    case 'content_filter':
      return {
        keywords: visual.keywords
          ? visual.keywords.split(',').map((s) => s.trim()).filter(Boolean)
          : [],
      };
    default:
      return {};
  }
}

function conditionsToVisual(
  ruleType: RuleType,
  conditions: Record<string, unknown>,
): Record<string, string> {
  switch (ruleType) {
    case 'pii_block':
    case 'pii_redact':
    case 'pii_synthetic':
      return { pii_types: ((conditions.pii_types as string[]) || []).join(', ') };
    case 'rate_limit':
      return {
        max_requests: String(conditions.max_requests ?? 100),
        window_seconds: String(conditions.window_seconds ?? 60),
      };
    case 'model_restrict':
      return { allowed_models: ((conditions.allowed_models as string[]) || []).join(', ') };
    case 'content_filter':
      return { keywords: ((conditions.keywords as string[]) || []).join(', ') };
    default:
      return {};
  }
}

function makeEmptyRule(): PolicyRuleForm {
  return {
    rule_type: 'pii_block',
    action: 'block',
    message: '',
    is_active: true,
    conditionsRaw: '{}',
    conditions: {},
    showRaw: false,
    expanded: true,
  };
}

function ruleFromApi(apiRule: ApiPolicyRule): PolicyRuleForm {
  const raw = JSON.stringify(apiRule.conditions ?? {}, null, 2);
  return {
    rule_type: apiRule.rule_type as RuleType,
    action: apiRule.action as PolicyAction,
    message: apiRule.message ?? '',
    is_active: apiRule.is_active ?? true,
    conditionsRaw: raw,
    conditions: apiRule.conditions ?? {},
    showRaw: false,
    expanded: false,
  };
}

// ─── ConditionsEditor ─────────────────────────────────────────────────────────

interface ConditionsEditorProps {
  rule: PolicyRuleForm;
  onChange: (updated: Partial<PolicyRuleForm>) => void;
}

function ConditionsEditor({ rule, onChange }: ConditionsEditorProps) {
  const [visual, setVisual] = useState<Record<string, string>>(
    conditionsToVisual(rule.rule_type, rule.conditions),
  );

  const applyVisual = (newVisual: Record<string, string>) => {
    setVisual(newVisual);
    const built = buildConditionsFromVisual(rule.rule_type, newVisual);
    onChange({
      conditions: built,
      conditionsRaw: JSON.stringify(built, null, 2),
    });
  };

  const applyRaw = (raw: string) => {
    try {
      const parsed = JSON.parse(raw);
      onChange({
        conditionsRaw: raw,
        conditions: parsed,
      });
    } catch {
      // invalid JSON - just store the raw string, don't update conditions
      onChange({ conditionsRaw: raw });
    }
  };

  const fieldClass = 'bg-neutral-950 border-neutral-700 text-neutral-100 text-xs';

  const renderVisual = () => {
    switch (rule.rule_type) {
      case 'pii_block':
      case 'pii_redact':
      case 'pii_synthetic':
        return (
          <div className="space-y-1">
            <label className="text-xs text-neutral-500">PII Types (comma-separated, e.g. EMAIL, PHONE)</label>
            <Input
              placeholder="EMAIL, PHONE, SSN"
              value={visual.pii_types ?? ''}
              onChange={(e) => applyVisual({ ...visual, pii_types: e.target.value })}
              className={fieldClass}
            />
          </div>
        );
      case 'rate_limit':
        return (
          <div className="grid grid-cols-2 gap-2">
            <div className="space-y-1">
              <label className="text-xs text-neutral-500">Max Requests</label>
              <Input
                type="number"
                placeholder="100"
                value={visual.max_requests ?? ''}
                onChange={(e) => applyVisual({ ...visual, max_requests: e.target.value })}
                className={fieldClass}
              />
            </div>
            <div className="space-y-1">
              <label className="text-xs text-neutral-500">Window (seconds)</label>
              <Input
                type="number"
                placeholder="60"
                value={visual.window_seconds ?? ''}
                onChange={(e) => applyVisual({ ...visual, window_seconds: e.target.value })}
                className={fieldClass}
              />
            </div>
          </div>
        );
      case 'model_restrict':
        return (
          <div className="space-y-1">
            <label className="text-xs text-neutral-500">Allowed Models (comma-separated)</label>
            <Input
              placeholder="gpt-4o, gpt-3.5-turbo"
              value={visual.allowed_models ?? ''}
              onChange={(e) => applyVisual({ ...visual, allowed_models: e.target.value })}
              className={fieldClass}
            />
          </div>
        );
      case 'content_filter':
        return (
          <div className="space-y-1">
            <label className="text-xs text-neutral-500">Blocked Terms (comma-separated)</label>
            <Input
              placeholder="violence, hate, weapons"
              value={visual.keywords ?? ''}
              onChange={(e) => applyVisual({ ...visual, keywords: e.target.value })}
              className={fieldClass}
            />
          </div>
        );
      case 'custom':
        return null; // Only raw JSON for custom
      default:
        return null;
    }
  };

  return (
    <div className="space-y-2">
      {rule.rule_type !== 'custom' && renderVisual()}

      {/* Raw JSON toggle */}
      <button
        type="button"
        onClick={() => onChange({ showRaw: !rule.showRaw })}
        className="flex items-center gap-1 text-xs text-neutral-500 hover:text-neutral-300 transition-colors"
      >
        <Code className="w-3 h-3" />
        {rule.showRaw ? 'Hide' : 'Show'} raw JSON conditions
      </button>

      {(rule.showRaw || rule.rule_type === 'custom') && (
        <textarea
          value={rule.conditionsRaw}
          onChange={(e) => applyRaw(e.target.value)}
          rows={4}
          placeholder="{}"
          className="w-full rounded-md bg-neutral-950 border border-neutral-700 text-neutral-100 font-mono text-xs p-2 resize-y focus:outline-none focus:border-blue-500"
        />
      )}
    </div>
  );
}

// ─── RuleCard ─────────────────────────────────────────────────────────────────

interface RuleCardProps {
  rule: PolicyRuleForm;
  index: number;
  total: number;
  onChange: (index: number, updated: Partial<PolicyRuleForm>) => void;
  onRemove: (index: number) => void;
  onMoveUp: (index: number) => void;
  onMoveDown: (index: number) => void;
}

function RuleCard({ rule, index, total, onChange, onRemove, onMoveUp, onMoveDown }: RuleCardProps) {
  const selectClass =
    'w-full rounded-md bg-neutral-950 border border-neutral-700 text-neutral-100 p-1.5 text-xs focus:outline-none focus:border-blue-500';

  const handleTypeChange = (newType: RuleType) => {
    const built = buildConditionsFromVisual(newType, {});
    onChange(index, {
      rule_type: newType,
      action: newType === 'pii_synthetic' || newType === 'pii_redact' ? 'allow' : rule.action,
      conditions: built,
      conditionsRaw: JSON.stringify(built, null, 2),
    });
  };

  return (
    <Card className="bg-neutral-950 border-neutral-700">
      <CardContent className="pt-4 pb-3 px-4 space-y-3">
        {/* Rule header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-neutral-500">#{index + 1}</span>
            <span className={`text-xs font-semibold ${ACTION_COLORS[rule.action]}`}>
              {ACTION_LABELS[rule.action]}
            </span>
            <span className="text-xs text-neutral-400">{RULE_TYPE_LABELS[rule.rule_type]}</span>
          </div>
          <div className="flex items-center gap-1">
            <button
              type="button"
              onClick={() => onMoveUp(index)}
              disabled={index === 0}
              className="p-1 text-neutral-500 hover:text-neutral-200 disabled:opacity-30"
              title="Move up"
            >
              <ChevronUp className="w-3 h-3" />
            </button>
            <button
              type="button"
              onClick={() => onMoveDown(index)}
              disabled={index === total - 1}
              className="p-1 text-neutral-500 hover:text-neutral-200 disabled:opacity-30"
              title="Move down"
            >
              <ChevronDown className="w-3 h-3" />
            </button>
            <button
              type="button"
              onClick={() => onChange(index, { expanded: !rule.expanded })}
              className="p-1 text-neutral-500 hover:text-neutral-200"
              title={rule.expanded ? 'Collapse' : 'Expand'}
            >
              {rule.expanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
            </button>
            <button
              type="button"
              onClick={() => onRemove(index)}
              className="p-1 text-neutral-500 hover:text-red-400"
              title="Remove rule"
            >
              <Trash2 className="w-3 h-3" />
            </button>
          </div>
        </div>

        {rule.expanded && (
          <>
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1">
                <label className="text-xs text-neutral-500">Rule Type</label>
                <select
                  value={rule.rule_type}
                  onChange={(e) => handleTypeChange(e.target.value as RuleType)}
                  className={selectClass}
                >
                  {(Object.keys(RULE_TYPE_LABELS) as RuleType[]).map((t) => (
                    <option key={t} value={t}>{RULE_TYPE_LABELS[t]}</option>
                  ))}
                </select>
              </div>
              <div className="space-y-1">
                <label className="text-xs text-neutral-500">Action</label>
                <select
                  value={rule.action}
                  onChange={(e) => onChange(index, { action: e.target.value as PolicyAction })}
                  className={selectClass}
                >
                  {(Object.keys(ACTION_LABELS) as PolicyAction[]).map((a) => (
                    <option key={a} value={a}>{ACTION_LABELS[a]}</option>
                  ))}
                </select>
              </div>
            </div>

            <div className="space-y-1">
              <label className="text-xs text-neutral-500">Violation Message (optional)</label>
              <Input
                placeholder="e.g. PII detected — request blocked."
                value={rule.message}
                onChange={(e) => onChange(index, { message: e.target.value })}
                className="bg-neutral-950 border-neutral-700 text-neutral-100 text-xs"
              />
            </div>

            <div className="space-y-1">
              <label className="text-xs text-neutral-500">Conditions</label>
              <ConditionsEditor
                key={rule.rule_type}
                rule={rule}
                onChange={(updated) => onChange(index, updated)}
              />
            </div>

            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id={`rule-active-${index}`}
                checked={rule.is_active}
                onChange={(e) => onChange(index, { is_active: e.target.checked })}
                className="rounded"
              />
              <label htmlFor={`rule-active-${index}`} className="text-xs text-neutral-400">
                Rule active
              </label>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

// ─── PolicyForm (exported) ────────────────────────────────────────────────────

interface PolicyFormProps {
  /** If provided, pre-populate form with existing policy data (edit mode) */
  initialData?: ApiPolicyData;
  onSubmit: (payload: PolicySubmitPayload) => Promise<void>;
  onCancel: () => void;
  isPending: boolean;
  mode: 'create' | 'edit';
}

export function PolicyForm({ initialData, onSubmit, onCancel, isPending, mode }: PolicyFormProps) {
  const [name, setName] = useState(initialData?.name ?? '');
  const [description, setDescription] = useState(initialData?.description ?? '');
  const [isActive, setIsActive] = useState(initialData?.is_active ?? true);
  const [priority, setPriority] = useState<number>(initialData?.priority ?? 0);
  const [rules, setRules] = useState<PolicyRuleForm[]>(
    initialData?.rules?.length
      ? initialData.rules.map(ruleFromApi)
      : [],
  );

  const updateRule = (index: number, updated: Partial<PolicyRuleForm>) => {
    setRules((prev) => prev.map((r, i) => (i === index ? { ...r, ...updated } : r)));
  };

  const addRule = () => setRules((prev) => [...prev, makeEmptyRule()]);

  const removeRule = (index: number) =>
    setRules((prev) => prev.filter((_, i) => i !== index));

  const moveRule = (index: number, direction: 'up' | 'down') => {
    setRules((prev) => {
      const next = [...prev];
      const target = direction === 'up' ? index - 1 : index + 1;
      if (target < 0 || target >= next.length) return prev;
      [next[index], next[target]] = [next[target], next[index]];
      return next;
    });
  };

  const handleSubmit = async () => {
    // Build the payload matching the backend schema
    const payload: PolicySubmitPayload = {
      name: name.trim(),
      description: description.trim() || null,
      is_active: isActive,
      priority,
      rules: rules.map((r) => {
        let conditions = r.conditions;
        // Try to parse raw JSON as the authoritative value when showRaw or custom
        if (r.showRaw || r.rule_type === 'custom') {
          try { conditions = JSON.parse(r.conditionsRaw) as Record<string, unknown>; } catch { /* ignore */ }
        }
        return {
          rule_type: r.rule_type,
          action: r.action,
          message: r.message || null,
          is_active: r.is_active,
          conditions,
        };
      }),
    };
    await onSubmit(payload);
  };

  return (
    <div className="space-y-5">
      {/* Policy Meta */}
      <div className="grid grid-cols-2 gap-3">
        <div className="col-span-2 space-y-1">
          <label className="text-xs text-neutral-500">Policy Name *</label>
          <Input
            placeholder="e.g. PII Protection Policy"
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="bg-neutral-950 border-neutral-700 text-neutral-100"
          />
        </div>
        <div className="col-span-2 space-y-1">
          <label className="text-xs text-neutral-500">Description</label>
          <Input
            placeholder="What does this policy do?"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            className="bg-neutral-950 border-neutral-700 text-neutral-100"
          />
        </div>
        <div className="space-y-1">
          <label className="text-xs text-neutral-500">Priority (higher = evaluated first)</label>
          <Input
            type="number"
            min={0}
            value={priority}
            onChange={(e) => setPriority(parseInt(e.target.value, 10) || 0)}
            className="bg-neutral-950 border-neutral-700 text-neutral-100"
          />
        </div>
        <div className="flex items-end pb-1">
          <label className="flex items-center gap-2 text-sm text-neutral-400 cursor-pointer">
            <input
              type="checkbox"
              checked={isActive}
              onChange={(e) => setIsActive(e.target.checked)}
              className="rounded"
            />
            Policy active
          </label>
        </div>
      </div>

      {/* Rules */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <span className="text-sm font-medium text-neutral-300">
            Rules ({rules.length})
          </span>
          <button
            type="button"
            onClick={addRule}
            className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 transition-colors"
          >
            <Plus className="w-3 h-3" />
            Add Rule
          </button>
        </div>

        {rules.length === 0 && (
          <p className="text-xs text-neutral-600 text-center py-4 border border-dashed border-neutral-800 rounded-lg">
            No rules yet. Add a rule to make this policy enforceable.
          </p>
        )}

        <div className="space-y-2">
          {rules.map((rule, idx) => (
            <RuleCard
              key={idx}
              rule={rule}
              index={idx}
              total={rules.length}
              onChange={updateRule}
              onRemove={removeRule}
              onMoveUp={(i) => moveRule(i, 'up')}
              onMoveDown={(i) => moveRule(i, 'down')}
            />
          ))}
        </div>
      </div>

      {/* Actions */}
      <div className="flex gap-2 pt-2">
        <Button
          onClick={handleSubmit}
          disabled={isPending || !name.trim()}
          className="bg-blue-600 hover:bg-blue-700"
        >
          {isPending ? (mode === 'create' ? 'Creating...' : 'Saving...') : (mode === 'create' ? 'Create Policy' : 'Save Changes')}
        </Button>
        <Button variant="ghost" onClick={onCancel} className="text-neutral-400">
          Cancel
        </Button>
      </div>
    </div>
  );
}
