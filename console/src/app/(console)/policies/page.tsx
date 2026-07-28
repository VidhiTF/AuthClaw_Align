"use client";

import React, { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Check,
  FileText,
  History,
  Play,
  Plus,
  RotateCcw,
  Save,
  ShieldAlert,
  Trash2,
} from "lucide-react";
import { getErrorMessage } from "@/lib/errors";

type RuleAction = "redact" | "warn" | "require_approval" | "block";
type RuleSeverity = "low" | "medium" | "high" | "critical";

interface RedactionRule {
  id: string;
  name: string;
  pattern: string;
  reason: string;
  severity: RuleSeverity;
  action: RuleAction;
}

interface PolicyVersion {
  id: string;
  name: string;
  version: number;
  is_active: boolean;
  created_at: string;
}

interface ParsedPolicyYaml {
  rules: RedactionRule[];
  modelWhitelist: string[];
  requestsPerMinute?: number;
}

interface PolicyValidationResult {
  valid: boolean;
  errors: Array<{ path: string; message: string }>;
  warnings: Array<{ path: string; message: string }>;
  stats?: Record<string, number | string | boolean>;
}

interface PolicySimulationResult {
  decision: "allow" | "warn" | "block" | "require_approval";
  allow: boolean;
  reason: string;
  explanations: Array<{
    stage: string;
    outcome: string;
    message: string;
    rule_name?: string;
    rule_type?: string;
    severity?: string;
    prompt_index?: number;
    matched_text_preview?: string;
  }>;
  matched_rules: Array<Record<string, string | number | boolean>>;
}

const defaultRules: RedactionRule[] = [
  {
    id: "email",
    name: "customer_email",
    pattern: "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b",
    reason: "Email addresses are redacted before model egress.",
    severity: "medium",
    action: "redact",
  },
  {
    id: "health",
    name: "patient_health_data",
    pattern: "(?i)\\b(patient|diagnosis|prescription|medical record)\\b",
    reason: "Health context requires human approval before model egress.",
    severity: "high",
    action: "require_approval",
  },
  {
    id: "ssn",
    name: "ssn_block",
    pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b",
    reason: "SSNs are blocked in the Lite demo policy.",
    severity: "critical",
    action: "block",
  },
];

function yamlQuote(value: string) {
  return `'${value.replace(/'/g, "''")}'`;
}

function newClientId() {
  return globalThis.crypto?.randomUUID?.() ?? `rule-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

function unquoteYamlScalar(value: string) {
  const trimmed = value.trim();
  if (trimmed.startsWith("'") && trimmed.endsWith("'")) {
    return trimmed.slice(1, -1).replace(/''/g, "'");
  }
  if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
    try {
      return JSON.parse(trimmed) as string;
    } catch {
      return trimmed.slice(1, -1);
    }
  }
  return trimmed;
}

function coerceRuleAction(value: string): RuleAction {
  return value === "warn" || value === "require_approval" || value === "block" ? value : "redact";
}

function coerceRuleSeverity(value: string): RuleSeverity {
  return value === "low" || value === "high" || value === "critical" ? value : "medium";
}

function parsePolicyYaml(yaml: string): ParsedPolicyYaml | null {
  const lines = yaml.split(/\r?\n/);
  const rules: RedactionRule[] = [];
  const modelWhitelist: string[] = [];
  let requestsPerMinute: number | undefined;
  let section = "";
  let inWhitelist = false;
  let currentRule: Partial<RedactionRule> | null = null;

  const pushRule = () => {
    if (!currentRule?.name && !currentRule?.pattern) return;
    rules.push({
      id: newClientId(),
      name: currentRule.name || "custom_rule",
      pattern: currentRule.pattern || "",
      reason: currentRule.reason || "Custom governance rule matched.",
      severity: currentRule.severity || "medium",
      action: currentRule.action || "redact",
    });
  };

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;

    if (line === "regex_rules:") {
      pushRule();
      currentRule = null;
      section = "regex";
      inWhitelist = false;
      continue;
    }
    if (line === "model_rules:") {
      pushRule();
      currentRule = null;
      section = "model";
      inWhitelist = false;
      continue;
    }
    if (line === "topic_rules:" || line.startsWith("topic_rules:")) {
      pushRule();
      currentRule = null;
      section = "topic";
      inWhitelist = false;
      continue;
    }
    if (line === "rate_limits:") {
      pushRule();
      currentRule = null;
      section = "rate";
      inWhitelist = false;
      continue;
    }

    if (section === "regex") {
      if (line.startsWith("- name:")) {
        pushRule();
        currentRule = { name: unquoteYamlScalar(line.slice("- name:".length)) };
        continue;
      }
      if (!currentRule) continue;
      if (line.startsWith("pattern:")) {
        currentRule.pattern = unquoteYamlScalar(line.slice("pattern:".length));
      } else if (line.startsWith("reason:")) {
        currentRule.reason = unquoteYamlScalar(line.slice("reason:".length));
      } else if (line.startsWith("severity:")) {
        currentRule.severity = coerceRuleSeverity(unquoteYamlScalar(line.slice("severity:".length)));
      } else if (line.startsWith("action:")) {
        currentRule.action = coerceRuleAction(unquoteYamlScalar(line.slice("action:".length)));
      }
      continue;
    }

    if (section === "model") {
      if (line === "whitelist:") {
        inWhitelist = true;
        continue;
      }
      if (line.startsWith("blacklist:")) {
        inWhitelist = false;
        continue;
      }
      if (inWhitelist && line.startsWith("- ")) {
        modelWhitelist.push(unquoteYamlScalar(line.slice(2)));
      }
      continue;
    }

    if (section === "rate" && line.startsWith("requests_per_minute:")) {
      const parsed = Number(unquoteYamlScalar(line.slice("requests_per_minute:".length)));
      if (Number.isFinite(parsed) && parsed > 0) {
        requestsPerMinute = parsed;
      }
    }
  }

  pushRule();
  return rules.length || modelWhitelist.length || requestsPerMinute ? { rules, modelWhitelist, requestsPerMinute } : null;
}

function buildPolicyYaml(rules: RedactionRule[], modelWhitelist: string[], requestsPerMinute: number) {
  const ruleYaml = rules
    .map((rule) => {
      const lines = [
        `  - name: ${rule.name || "unnamed_rule"}`,
        `    pattern: ${yamlQuote(rule.pattern)}`,
        `    reason: ${yamlQuote(rule.reason || "Custom governance rule matched.")}`,
        `    severity: ${rule.severity}`,
        `    action: ${rule.action}`,
      ];
      if (rule.action === "require_approval") {
        lines.push("    hitl_timeout_seconds: 1800");
      }
      return lines.join("\n");
    })
    .join("\n");

  const whitelistYaml = modelWhitelist.length
    ? modelWhitelist.map((model) => `    - ${model}`).join("\n")
    : "    []";

  return `regex_rules:\n${ruleYaml || "  []"}\n\nmodel_rules:\n  whitelist:\n${whitelistYaml}\n  blacklist: []\n\ntopic_rules: []\n\nrate_limits:\n  requests_per_minute: ${requestsPerMinute}`;
}

export default function PoliciesPage() {
  const [rules, setRules] = useState<RedactionRule[]>(defaultRules);
  const [policyName, setPolicyName] = useState("AuthClaw Lite Governance Policy");
  const [policyDesc, setPolicyDesc] = useState("Custom redaction, HITL approval, and block rules for gateway traffic.");
  const [modelInput, setModelInput] = useState("gpt-4o-mini, gemini-2.5-flash-lite");
  const [requestsPerMinute, setRequestsPerMinute] = useState(60);
  const [activeYaml, setActiveYaml] = useState("");
  const [history, setHistory] = useState<PolicyVersion[]>([]);
  const [saving, setSaving] = useState(false);
  const [validating, setValidating] = useState(false);
  const [simulating, setSimulating] = useState(false);
  const [activatingId, setActivatingId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [validationResult, setValidationResult] = useState<PolicyValidationResult | null>(null);
  const [simulationResult, setSimulationResult] = useState<PolicySimulationResult | null>(null);
  const [simulationModel, setSimulationModel] = useState("gemini-2.5-flash-lite");
  const [simulationPrompt, setSimulationPrompt] = useState("My patient diagnosis is confidential.");
  const [simulationTopics, setSimulationTopics] = useState("");

  const modelWhitelist = useMemo(
    () => modelInput.split(",").map((model) => model.trim()).filter(Boolean),
    [modelInput]
  );
  const generatedYaml = useMemo(
    () => buildPolicyYaml(rules, modelWhitelist, requestsPerMinute),
    [rules, modelWhitelist, requestsPerMinute]
  );

  const fetchHistory = async () => {
    const res = await fetch("/api/policies");
    if (res.status === 401) {
      window.location.href = "/login";
      return;
    }
    if (!res.ok) throw new Error("Failed to load policy history");
    const data = await res.json();
    setHistory(data || []);
  };

  useEffect(() => {
    const initialFetch = window.setTimeout(async () => {
      try {
        const [activeRes] = await Promise.all([
          fetch("/api/policies/active"),
          fetchHistory(),
        ]);
        if (activeRes.ok) {
          const active = await activeRes.json();
          const policyYaml = active.policy_yaml || "";
          setActiveYaml(policyYaml);
          setPolicyName(active.name || "AuthClaw Lite Governance Policy");
          setPolicyDesc(active.description || "Custom redaction, HITL approval, and block rules for gateway traffic.");
          const parsed = parsePolicyYaml(policyYaml);
          if (parsed) {
            if (parsed.rules.length > 0) {
              setRules(parsed.rules);
            }
            if (parsed.modelWhitelist.length > 0) {
              setModelInput(parsed.modelWhitelist.join(", "));
            }
            if (parsed.requestsPerMinute) {
              setRequestsPerMinute(parsed.requestsPerMinute);
            }
          }
        }
      } catch (err: unknown) {
        console.warn("Policy bootstrap failed:", getErrorMessage(err, "Policy bootstrap failed"));
      } finally {
        setLoading(false);
      }
    }, 0);

    return () => window.clearTimeout(initialFetch);
  }, []);

  const addRule = () => {
    setRules((current) => [
      ...current,
      {
        id: newClientId(),
        name: "custom_rule",
        pattern: "(?i)custom sensitive phrase",
        reason: "Custom sensitive content matched.",
        severity: "medium",
        action: "redact",
      },
    ]);
  };

  const updateRule = (id: string, patch: Partial<RedactionRule>) => {
    setRules((current) => current.map((rule) => (rule.id === id ? { ...rule, ...patch } : rule)));
  };

  const removeRule = (id: string) => {
    setRules((current) => current.filter((rule) => rule.id !== id));
  };

  const savePolicy = async () => {
    setSaving(true);
    setError(null);
    setMessage(null);
    try {
      const res = await fetch("/api/policies", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: policyName,
          description: policyDesc,
          policy_yaml: generatedYaml,
          activate: true,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || data.detail || "Policy validation failed");
      }
      setActiveYaml(generatedYaml);
      setMessage("Policy deployed. Gateway will use these rules on the next request.");
      await fetchHistory();
    } catch (err: unknown) {
      setError(getErrorMessage(err, "Failed to save policy"));
    } finally {
      setSaving(false);
    }
  };

  const validateGeneratedPolicy = async () => {
    setValidating(true);
    setError(null);
    setMessage(null);
    setValidationResult(null);
    try {
      const res = await fetch("/api/policies/validate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ policy_yaml: generatedYaml }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || data.detail?.message || "Policy validation failed");
      }
      setValidationResult(data);
      setMessage(data.valid ? "Policy validation passed." : "Policy validation returned issues.");
    } catch (err: unknown) {
      setError(getErrorMessage(err, "Failed to validate policy"));
    } finally {
      setValidating(false);
    }
  };

  const simulateGeneratedPolicy = async () => {
    setSimulating(true);
    setError(null);
    setMessage(null);
    setSimulationResult(null);
    try {
      const res = await fetch("/api/policies/simulate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          policy_yaml: generatedYaml,
          model: simulationModel,
          route: "/v1/chat/completions",
          prompts: [simulationPrompt],
          topics: simulationTopics.split(",").map((topic) => topic.trim()).filter(Boolean),
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || data.detail?.message || "Policy simulation failed");
      }
      setValidationResult(data.validation);
      setSimulationResult(data);
      setMessage(`Simulation result: ${data.decision.replace("_", " ")}.`);
    } catch (err: unknown) {
      setError(getErrorMessage(err, "Failed to simulate policy"));
    } finally {
      setSimulating(false);
    }
  };

  const activateVersion = async (id: string) => {
    setActivatingId(id);
    setError(null);
    setMessage(null);
    try {
      const res = await fetch(`/api/policies/${id}/activate`, { method: "POST" });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || data.detail || "Failed to activate policy");
      }
      setActiveYaml(data.policy_yaml || activeYaml);
      setMessage(`Policy v${data.version} activated.`);
      await fetchHistory();
    } catch (err: unknown) {
      setError(getErrorMessage(err, "Failed to activate policy version"));
    } finally {
      setActivatingId(null);
    }
  };

  const rollbackPrevious = async () => {
    setActivatingId("rollback");
    setError(null);
    setMessage(null);
    try {
      const res = await fetch("/api/policies/rollback", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || data.detail || "Failed to rollback policy");
      }
      setActiveYaml(data.policy_yaml || activeYaml);
      setMessage(`Rolled back to policy v${data.version}.`);
      await fetchHistory();
    } catch (err: unknown) {
      setError(getErrorMessage(err, "Failed to rollback policy"));
    } finally {
      setActivatingId(null);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-extrabold tracking-tight text-[#0E1726]">Custom Redaction Policy</h1>
          <p className="text-[#6B7488] text-sm mt-1">
            Build easy gateway rules for redaction, human approval, or immediate blocking.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => void validateGeneratedPolicy()}
            disabled={validating || loading}
            className="inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-[#F5F7FA] hover:bg-[#EEF1F6] text-[#0E1726] font-semibold text-xs transition disabled:opacity-50"
          >
            <Check className="w-4 h-4" />
            {validating ? "Validating..." : "Validate"}
          </button>
          <button
            onClick={() => void simulateGeneratedPolicy()}
            disabled={simulating || loading}
            className="inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-[#F5F7FA] hover:bg-[#EEF1F6] text-[#0E1726] font-semibold text-xs transition disabled:opacity-50"
          >
            <Play className="w-4 h-4" />
            {simulating ? "Simulating..." : "Dry Run"}
          </button>
          <button
            onClick={() => void savePolicy()}
            disabled={saving || loading || rules.length === 0}
            className="inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs shadow-lg transition disabled:opacity-50"
          >
            <Save className="w-4 h-4" />
            {saving ? "Deploying..." : "Validate & Deploy"}
          </button>
        </div>
      </div>

      {message && (
        <div className="p-4 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-200 text-xs flex items-start gap-3">
          <Check className="w-4 h-4 text-emerald-400" />
          {message}
        </div>
      )}
      {error && (
        <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/20 text-red-200 text-xs flex items-start gap-3">
          <AlertTriangle className="w-4 h-4 text-red-400" />
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <section className="xl:col-span-2 space-y-4">
          <div className="rounded-lg bg-white border border-[#E6E9F0] p-5 space-y-4">
            <div className="flex items-center justify-between gap-4">
              <div>
                <div className="flex items-center gap-2 text-[#0E1726] text-sm font-bold">
                  <ShieldAlert className="w-4 h-4 text-amber-400" />
                  Rule Builder
                </div>
                <p className="text-xs text-[#6B7488] mt-1">Rules run before model provider egress.</p>
              </div>
              <button
                onClick={addRule}
                className="inline-flex items-center gap-2 px-3 py-2 rounded-lg bg-[#F5F7FA] hover:bg-[#EEF1F6] text-xs font-semibold text-[#0E1726]"
              >
                <Plus className="w-4 h-4" />
                Add Rule
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <label className="block">
                <span className="block text-[10px] uppercase tracking-wider font-bold text-[#6B7488] mb-1.5">Policy Name</span>
                <input
                  value={policyName}
                  onChange={(event) => setPolicyName(event.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-[#F5F7FA] border border-[#E6E9F0] text-[#0E1726] text-xs focus:outline-none focus:border-indigo-500"
                />
              </label>
              <label className="block">
                <span className="block text-[10px] uppercase tracking-wider font-bold text-[#6B7488] mb-1.5">Allowed Models</span>
                <input
                  value={modelInput}
                  onChange={(event) => setModelInput(event.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-[#F5F7FA] border border-[#E6E9F0] text-[#0E1726] text-xs focus:outline-none focus:border-indigo-500"
                />
              </label>
            </div>

            <label className="block">
              <span className="block text-[10px] uppercase tracking-wider font-bold text-[#6B7488] mb-1.5">Description</span>
              <input
                value={policyDesc}
                onChange={(event) => setPolicyDesc(event.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-[#F5F7FA] border border-[#E6E9F0] text-[#0E1726] text-xs focus:outline-none focus:border-indigo-500"
              />
            </label>

            <label className="block max-w-xs">
              <span className="block text-[10px] uppercase tracking-wider font-bold text-[#6B7488] mb-1.5">Rate Limit / Minute</span>
              <input
                type="number"
                min={1}
                max={1000}
                value={requestsPerMinute}
                onChange={(event) => setRequestsPerMinute(Number(event.target.value))}
                className="w-full px-3 py-2 rounded-lg bg-[#F5F7FA] border border-[#E6E9F0] text-[#0E1726] text-xs focus:outline-none focus:border-indigo-500"
              />
            </label>
          </div>

          <div className="rounded-lg bg-white border border-[#E6E9F0] p-5 space-y-4">
            <div className="flex items-center gap-2 text-[#0E1726] text-sm font-bold">
              <Play className="w-4 h-4 text-indigo-400" />
              Dry-Run Simulation
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <label className="block">
                <span className="block text-[10px] uppercase tracking-wider font-bold text-[#6B7488] mb-1.5">Model</span>
                <input
                  value={simulationModel}
                  onChange={(event) => setSimulationModel(event.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-[#F5F7FA] border border-[#E6E9F0] text-[#0E1726] text-xs focus:outline-none focus:border-indigo-500"
                />
              </label>
              <label className="block">
                <span className="block text-[10px] uppercase tracking-wider font-bold text-[#6B7488] mb-1.5">Topics</span>
                <input
                  value={simulationTopics}
                  onChange={(event) => setSimulationTopics(event.target.value)}
                  placeholder="medical, finance"
                  className="w-full px-3 py-2 rounded-lg bg-[#F5F7FA] border border-[#E6E9F0] text-[#0E1726] text-xs focus:outline-none focus:border-indigo-500"
                />
              </label>
            </div>
            <label className="block">
              <span className="block text-[10px] uppercase tracking-wider font-bold text-[#6B7488] mb-1.5">Prompt</span>
              <textarea
                value={simulationPrompt}
                onChange={(event) => setSimulationPrompt(event.target.value)}
                rows={3}
                className="w-full px-3 py-2 rounded-lg bg-[#F5F7FA] border border-[#E6E9F0] text-[#0E1726] text-xs focus:outline-none focus:border-indigo-500"
              />
            </label>
          </div>

          <div className="space-y-3">
            {rules.map((rule) => (
              <div key={rule.id} className="rounded-lg bg-white border border-[#E6E9F0] p-5 space-y-4">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <h3 className="text-sm font-bold text-[#0E1726]">{rule.name || "Unnamed rule"}</h3>
                    <p className="text-xs text-[#6B7488] mt-1">{rule.reason || "No reason provided."}</p>
                  </div>
                  <button
                    onClick={() => removeRule(rule.id)}
                    className="p-2 rounded-lg bg-red-500/10 hover:bg-red-500/20 border border-red-500/20 text-red-300"
                    aria-label="Remove rule"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  <label className="block">
                    <span className="block text-[10px] uppercase tracking-wider font-bold text-[#6B7488] mb-1.5">Rule Name</span>
                    <input
                      value={rule.name}
                      onChange={(event) => updateRule(rule.id, { name: event.target.value.replace(/\s+/g, "_") })}
                      className="w-full px-3 py-2 rounded-lg bg-[#F5F7FA] border border-[#E6E9F0] text-[#0E1726] text-xs focus:outline-none focus:border-indigo-500"
                    />
                  </label>
                  <label className="block">
                    <span className="block text-[10px] uppercase tracking-wider font-bold text-[#6B7488] mb-1.5">Action</span>
                    <select
                      value={rule.action}
                      onChange={(event) => updateRule(rule.id, { action: event.target.value as RuleAction })}
                      className="w-full px-3 py-2 rounded-lg bg-[#F5F7FA] border border-[#E6E9F0] text-[#0E1726] text-xs focus:outline-none focus:border-indigo-500"
                    >
                      <option value="redact">Redact and pass</option>
                      <option value="warn">Warn, redact, and pass</option>
                      <option value="require_approval">Require HITL approval</option>
                      <option value="block">Block immediately</option>
                    </select>
                  </label>
                  <label className="block">
                    <span className="block text-[10px] uppercase tracking-wider font-bold text-[#6B7488] mb-1.5">Severity</span>
                    <select
                      value={rule.severity}
                      onChange={(event) => updateRule(rule.id, { severity: event.target.value as RuleSeverity })}
                      className="w-full px-3 py-2 rounded-lg bg-[#F5F7FA] border border-[#E6E9F0] text-[#0E1726] text-xs focus:outline-none focus:border-indigo-500"
                    >
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                      <option value="critical">Critical</option>
                    </select>
                  </label>
                </div>

                <label className="block">
                  <span className="block text-[10px] uppercase tracking-wider font-bold text-[#6B7488] mb-1.5">Regex Pattern</span>
                  <input
                    value={rule.pattern}
                    onChange={(event) => updateRule(rule.id, { pattern: event.target.value })}
                    className="w-full px-3 py-2 rounded-lg bg-[#F5F7FA] border border-[#E6E9F0] text-[#0E1726] text-xs font-mono focus:outline-none focus:border-indigo-500"
                  />
                </label>

                <label className="block">
                  <span className="block text-[10px] uppercase tracking-wider font-bold text-[#6B7488] mb-1.5">Reason Shown In Audit / HITL</span>
                  <input
                    value={rule.reason}
                    onChange={(event) => updateRule(rule.id, { reason: event.target.value })}
                    className="w-full px-3 py-2 rounded-lg bg-[#F5F7FA] border border-[#E6E9F0] text-[#0E1726] text-xs focus:outline-none focus:border-indigo-500"
                  />
                </label>
              </div>
            ))}
          </div>
        </section>

        <aside className="space-y-4">
          {validationResult && (
            <section className="rounded-lg bg-white border border-[#E6E9F0] p-4">
              <div className="flex items-center gap-2 mb-3">
                <Check className={validationResult.valid ? "w-4 h-4 text-emerald-400" : "w-4 h-4 text-red-400"} />
                <h2 className="text-sm font-bold text-[#0E1726]">Validation</h2>
              </div>
              <p className={`text-xs font-semibold ${validationResult.valid ? "text-emerald-300" : "text-red-300"}`}>
                {validationResult.valid ? "Valid and activation-safe" : "Invalid policy"}
              </p>
              {validationResult.errors.length > 0 && (
                <div className="mt-3 space-y-1">
                  {validationResult.errors.map((item, idx) => (
                    <p key={`${item.path}-${idx}`} className="text-[11px] text-red-200">
                      {item.path}: {item.message}
                    </p>
                  ))}
                </div>
              )}
              {validationResult.warnings.length > 0 && (
                <div className="mt-3 space-y-1">
                  {validationResult.warnings.map((item, idx) => (
                    <p key={`${item.path}-${idx}`} className="text-[11px] text-amber-200">
                      {item.path}: {item.message}
                    </p>
                  ))}
                </div>
              )}
            </section>
          )}

          {simulationResult && (
            <section className="rounded-lg bg-white border border-[#E6E9F0] p-4">
              <div className="flex items-center gap-2 mb-3">
                <Play className="w-4 h-4 text-indigo-400" />
                <h2 className="text-sm font-bold text-[#0E1726]">Dry-Run Result</h2>
              </div>
              <p className={`text-xs font-bold uppercase ${
                simulationResult.decision === "allow" ? "text-emerald-300" : simulationResult.decision === "block" ? "text-red-300" : "text-amber-300"
              }`}>
                {simulationResult.decision.replace("_", " ")}
              </p>
              <p className="text-xs text-[#6B7488] mt-2">{simulationResult.reason}</p>
              <div className="mt-3 space-y-2">
                {simulationResult.explanations.slice(0, 5).map((item, idx) => (
                  <div key={`${item.stage}-${idx}`} className="rounded border border-[#E6E9F0] bg-[#F5F7FA] p-2">
                    <p className="text-[10px] uppercase text-[#6B7488]">{item.stage} / {item.outcome}</p>
                    <p className="text-[11px] text-[#475069] mt-1">{item.message}</p>
                  </div>
                ))}
              </div>
            </section>
          )}

          <section className="rounded-lg bg-white border border-[#E6E9F0] overflow-hidden">
            <div className="px-4 py-3 border-b border-[#E6E9F0] flex items-center gap-2">
              <FileText className="w-4 h-4 text-indigo-400" />
              <h2 className="text-sm font-bold text-[#0E1726]">Generated YAML</h2>
            </div>
            <pre className="p-4 bg-[#F5F7FA] text-[11px] text-[#475069] overflow-x-auto max-h-[460px]">
              <code>{generatedYaml}</code>
            </pre>
          </section>

          <section className="rounded-lg bg-white border border-[#E6E9F0] p-4">
            <div className="flex items-center gap-2 mb-3">
              <History className="w-4 h-4 text-indigo-400" />
              <h2 className="text-sm font-bold text-[#0E1726]">Deploy History</h2>
            </div>
            <button
              onClick={() => void rollbackPrevious()}
              disabled={activatingId === "rollback" || history.filter((item) => !item.is_active).length === 0}
              className="mb-3 inline-flex items-center gap-2 px-3 py-2 rounded-lg bg-[#F5F7FA] hover:bg-[#EEF1F6] text-xs font-semibold text-[#0E1726] disabled:opacity-50"
            >
              <RotateCcw className="w-4 h-4" />
              {activatingId === "rollback" ? "Rolling back..." : "Rollback Previous"}
            </button>
            {history.length === 0 ? (
              <p className="text-xs text-[#6B7488]">No saved policy versions yet.</p>
            ) : (
              <div className="space-y-2">
                {history.slice(0, 6).map((policy) => (
                  <div key={policy.id} className="rounded border border-[#E6E9F0] bg-[#F5F7FA] px-3 py-2">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-semibold text-[#0E1726] truncate">{policy.name}</span>
                      <span className={`text-[10px] ${policy.is_active ? "text-emerald-300" : "text-[#6B7488]"}`}>
                        v{policy.version}{policy.is_active ? " active" : ""}
                      </span>
                    </div>
                    <p className="text-[10px] text-[#6B7488] mt-1">{new Date(policy.created_at).toLocaleString()}</p>
                    {!policy.is_active && (
                      <button
                        onClick={() => void activateVersion(policy.id)}
                        disabled={Boolean(activatingId)}
                        className="mt-2 inline-flex items-center gap-1 px-2 py-1 rounded border border-indigo-200 bg-indigo-50 text-[10px] font-semibold text-indigo-700 hover:bg-indigo-100 disabled:border-[#E6E9F0] disabled:bg-[#EEF1F6] disabled:text-[#8A94A6]"
                      >
                        <Check className="w-3 h-3" />
                        {activatingId === policy.id ? "Activating..." : "Activate"}
                      </button>
                    )}
                  </div>
                ))}
              </div>
            )}
          </section>

          {activeYaml && (
            <section className="rounded-lg bg-white border border-[#E6E9F0] p-4">
              <h2 className="text-sm font-bold text-[#0E1726] mb-2">Active Policy Loaded</h2>
              <p className="text-xs text-[#6B7488]">
                The builder is hydrated from the active deployed YAML and will replace it when you deploy changes.
              </p>
            </section>
          )}
        </aside>
      </div>
    </div>
  );
}
