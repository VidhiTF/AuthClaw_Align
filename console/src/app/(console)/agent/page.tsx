"use client";

import React, { useState, useEffect, useRef } from "react";
import {
  Bot,
  Send,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  User,
  Loader2,
  Terminal,
  Activity,
  Plus,
  MessageSquare,
  ExternalLink,
  BookOpen
} from "lucide-react";
import MfaChallengeModal from "@/components/mfa-challenge-modal";
import { getErrorMessage } from "@/lib/errors";

interface Workflow {
  id: string;
  workflow_id: string;
  framework: string;
  current_state: string;
  execution_status: string;
  risk_score: number | null;
  findings?: Finding[];
  remediation_plan?: RemediationPlan[];
  remediation_state?: string | null;
  remediation_actions?: RemediationAction[];
  rollback_result?: RollbackResult | null;
  execution_result?: RemediationExecutionResult | null;
  error_message?: string | null;
  retry_count?: number;
  state_data?: WorkflowStateData;
  started_at: string;
  completed_at: string | null;
  approval_id: string | null;
}

interface Approval {
  id: string;
  action_id: string;
  action_type: string;
  action_description: string;
  action_payload?: {
    plan?: RemediationPlan[];
  };
  status: string;
  expires_at: string;
  created_at: string;
}

interface Message {
  sender: "user" | "agent";
  text: string;
  timestamp: Date;
  results?: AgentResult;
}

interface ChatSession {
  id: string;
  title: string;
}

interface AgentRemediationFinding {
  id: number;
  provider: string;
  resource_id: string;
  finding_type: string;
  finding: string;
  recommendation: string;
  severity: string;
  status: string;
}

interface AgentRemediationSummary {
  connectors: unknown[];
  findings: AgentRemediationFinding[];
}

interface ChatHistoryMessage {
  sender: "user" | "agent";
  text: string;
  timestamp: string;
  results?: AgentResult;
}

interface Finding {
  control?: string;
  status?: string;
  description?: string;
  evidence?: string;
}

interface RemediationPlan {
  action?: string;
  priority?: string;
  finding_control?: string;
  estimated_effort?: string;
  destructive?: boolean;
  target?: RemediationTarget;
  diff?: RemediationDiff;
}

interface RemediationTarget {
  provider?: string;
  type?: string;
  bucket?: string;
  object_key?: string;
  uri?: string;
}

interface RemediationDiff {
  kind?: string;
  summary?: string;
  commands?: string[];
  preview?: string[];
}

interface RAGCitation {
  id: string;
  framework: string;
  section_id: string;
  label: string;
  title: string;
  source_name: string;
  url: string;
  score: number;
}

interface RAGChunk extends RAGCitation {
  text: string;
}

interface RAGAnswerResult {
  type: "rag_answer";
  question: string;
  corpus_version?: string | null;
  corpus_checksum?: string | null;
  grounded: boolean;
  citations: RAGCitation[];
  retrieved_chunks: RAGChunk[];
}

interface AgentTraceEvent {
  agent?: string;
  event?: string;
  details?: string;
  request_id?: string;
  sequence?: number;
}

interface AgentExecutionResult {
  request_id: string;
  status?: string;
  response?: string;
  risk_level?: string;
  provider?: string;
  model?: string;
  route_id?: string | null;
  decision?: string | null;
  reason?: string;
  category?: string;
  approval_id?: string;
  trace?: AgentTraceEvent[];
}

interface RemediationAction {
  id?: string;
  finding_control?: string;
  action?: string;
  target?: RemediationTarget;
  diff?: RemediationDiff;
  destructive?: boolean;
  status?: string;
  attempts?: number;
  completed_at?: string;
  last_error?: string;
  rollback_plan?: {
    mode?: string;
  };
  rollback_result?: {
    status?: string;
    details?: string;
  };
  result?: {
    control?: string;
    details?: string;
    mutation_id?: string;
    target?: RemediationTarget;
    cli_diff?: RemediationDiff;
    before_verification?: {
      total?: number;
    };
    after_verification?: {
      total?: number;
    };
  };
}

interface RollbackResult {
  rollback_successful?: number;
  rollback_failed?: number;
}

interface RemediationExecutionResult {
  remediation_state?: string;
  actions_successful?: number;
  actions_executed?: number;
  actions?: RemediationAction[];
}

interface WorkflowStateData {
  remediation_actions?: RemediationAction[];
  rollback_result?: RollbackResult | null;
}

type WorkflowInspection = Partial<Workflow> & {
  workflow_id?: string;
};

type AgentResult = WorkflowInspection | RAGAnswerResult | AgentExecutionResult;

const isRagResult = (result?: AgentResult | null): result is RAGAnswerResult => {
  return Boolean(result && "type" in result && result.type === "rag_answer");
};

const isWorkflowResult = (result?: AgentResult | null): result is WorkflowInspection => {
  return Boolean(result && "workflow_id" in result && result.workflow_id);
};

const isAgentExecutionResult = (result?: AgentResult | null): result is AgentExecutionResult => {
  return Boolean(result && "request_id" in result && result.request_id && !("workflow_id" in result));
};

const formatStateLabel = (value?: string | null) => {
  if (!value) return "Not Started";
  return value.replace(/_/g, " ").toLowerCase().replace(/\b\w/g, (char) => char.toUpperCase());
};

const getRemediationActions = (workflow?: WorkflowInspection | null): RemediationAction[] => {
  return workflow?.remediation_actions || workflow?.execution_result?.actions || workflow?.state_data?.remediation_actions || [];
};

const getRollbackResult = (workflow?: WorkflowInspection | null): RollbackResult | null => {
  return workflow?.rollback_result || workflow?.state_data?.rollback_result || null;
};

const getActionStatusClass = (status?: string) => {
  switch (status) {
    case "SUCCEEDED":
    case "ROLLED_BACK":
      return "bg-emerald-500/10 text-emerald-400 border-emerald-500/20";
    case "FAILED":
    case "ROLLBACK_FAILED":
      return "bg-red-500/10 text-red-400 border-red-500/20";
    case "RUNNING":
      return "bg-sky-500/10 text-sky-400 border-sky-500/20 animate-pulse";
    default:
      return "bg-[#F5F7FA]/70 text-[#6B7488] border-[#E6E9F0]";
  }
};

function RemediationTimeline({ workflow }: { workflow: WorkflowInspection }) {
  const actions = getRemediationActions(workflow);
  const rollback = getRollbackResult(workflow);
  const result = workflow?.execution_result || {};
  const remediationState = workflow?.remediation_state || result.remediation_state || "NOT_STARTED";

  if (!actions.length && !workflow?.approval_id && !workflow?.error_message) {
    return (
      <div className="space-y-2 text-[10px] text-[#6B7488]">
        <div className="flex items-center gap-2">
          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
          <span>Initial scan completed.</span>
        </div>
        <div className="flex items-center gap-2">
          <Activity className="w-3.5 h-3.5 text-[#6B7488]" />
          <span>No remediation has been applied yet.</span>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#E6E9F0] pb-2">
        <div>
          <p className="text-[9px] font-bold uppercase tracking-wider text-[#6B7488]">State Machine</p>
          <p className="text-[#475069] font-bold">{formatStateLabel(remediationState)}</p>
        </div>
        <div className="flex flex-wrap gap-2 text-[9px]">
          <span className="px-2 py-0.5 rounded-full border border-[#E6E9F0] bg-[#F5F7FA]/40 text-[#6B7488]">
            {result.actions_successful ?? 0}/{result.actions_executed ?? actions.length} successful
          </span>
          {typeof workflow?.retry_count === "number" && workflow.retry_count > 0 && (
            <span className="px-2 py-0.5 rounded-full border border-amber-500/20 bg-amber-500/10 text-amber-400">
              {workflow.retry_count} retr{workflow.retry_count === 1 ? "y" : "ies"}
            </span>
          )}
        </div>
      </div>

      {workflow?.approval_id && !actions.length && (
        <div className="flex items-center gap-2 text-[10px] text-amber-400">
          <AlertTriangle className="w-3.5 h-3.5" />
          <span>Awaiting approval: {workflow.approval_id}</span>
        </div>
      )}

      {actions.length > 0 && (
        <div className="space-y-2">
          {actions.map((action: RemediationAction, idx: number) => (
            <div key={action.id || idx} className="relative pl-5">
              <div className="absolute left-1.5 top-1 h-full w-px bg-[#F5F7FA]" />
              <div className={`absolute left-0 top-1.5 h-3 w-3 rounded-full border ${
                action.status === "FAILED" || action.status === "ROLLBACK_FAILED"
                  ? "bg-red-500/20 border-red-400"
                  : action.status === "SUCCEEDED" || action.status === "ROLLED_BACK"
                    ? "bg-emerald-500/20 border-emerald-400"
                    : "bg-sky-500/20 border-sky-400"
              }`} />
              <div className="rounded border border-[#E6E9F0] bg-[#F5F7FA] p-2.5 space-y-1.5">
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <p className="font-mono text-[10px] text-[#475069] break-all">{action.target?.uri || action.result?.target?.uri || action.finding_control || action.result?.control || "Unknown control"}</p>
                    <p className="text-[10px] text-[#6B7488] leading-normal">{action.action || action.result?.details || "Remediation action"}</p>
                  </div>
                  <span className={`shrink-0 px-1.5 py-0.5 rounded border text-[8px] font-black uppercase ${getActionStatusClass(action.status)}`}>
                    {formatStateLabel(action.status)}
                  </span>
                </div>
                <div className="flex flex-wrap gap-2 text-[9px] text-[#6B7488]">
                  <span>Attempts: {action.attempts || 0}</span>
                  {action.completed_at && <span>Completed: {new Date(action.completed_at).toLocaleTimeString()}</span>}
                  {action.result?.mutation_id && <span>Mutation: {action.result.mutation_id}</span>}
                  {action.last_error && <span className="text-red-400">Error: {action.last_error}</span>}
                </div>
                {(action.result?.before_verification || action.result?.after_verification) && (
                  <div className="grid grid-cols-2 gap-2 text-[9px]">
                    <div className="rounded border border-red-500/10 bg-red-500/5 p-2 text-red-400">
                      Before: {action.result?.before_verification?.total ?? 0} sensitive match{(action.result?.before_verification?.total ?? 0) === 1 ? "" : "es"}
                    </div>
                    <div className="rounded border border-emerald-500/10 bg-emerald-500/5 p-2 text-emerald-400">
                      After: {action.result?.after_verification?.total ?? 0} sensitive match{(action.result?.after_verification?.total ?? 0) === 1 ? "" : "es"}
                    </div>
                  </div>
                )}
                {(action.diff?.commands?.[0] || action.result?.cli_diff?.commands?.[0]) && (
                  <div className="rounded border border-[#E6E9F0] bg-white p-2 font-mono text-[9px] text-[#6B7488] break-all">
                    {(action.diff?.commands || action.result?.cli_diff?.commands || []).slice(0, 3).join("\n")}
                  </div>
                )}
                {action.rollback_result && (
                  <div className="rounded border border-emerald-500/10 bg-emerald-500/5 p-2 text-[9px] text-emerald-300 leading-normal">
                    Rollback: {action.rollback_result.details || action.rollback_result.status}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {rollback && (
        <div className="rounded border border-[#E6E9F0] bg-[#F5F7FA]/50 p-2.5 text-[10px] space-y-1">
          <div className="flex items-center gap-2 text-[#475069] font-bold">
            {(rollback.rollback_failed || 0) > 0 ? (
              <XCircle className="w-3.5 h-3.5 text-red-400" />
            ) : (
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            )}
            <span>Rollback Result</span>
          </div>
          <p className="text-[#6B7488]">
            {rollback.rollback_successful || 0} succeeded, {rollback.rollback_failed || 0} failed.
          </p>
        </div>
      )}

      {workflow?.error_message && (
        <div className="rounded border border-red-500/20 bg-red-500/10 p-2 text-[10px] text-red-300">
          {workflow.error_message}
        </div>
      )}
    </div>
  );
}

function AgentRemediationStatus({ summary, error }: { summary: AgentRemediationSummary | null; error: string | null }) {
  return (
    <div className="rounded-xl border border-[#E6E9F0] bg-white p-4 text-xs space-y-3">
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="font-bold text-[#0E1726]">Agent Service Remediation</p>
          <p className="mt-0.5 text-[10px] text-[#6B7488]">Read-only connector findings reported directly by services/agent.</p>
        </div>
        <span className={`rounded-full border px-2 py-0.5 text-[9px] font-bold uppercase ${
          error
            ? "border-red-500/20 bg-red-500/10 text-red-400"
            : "border-emerald-500/20 bg-emerald-500/10 text-emerald-500"
        }`}>
          {error ? "Unavailable" : "Connected"}
        </span>
      </div>
      {error ? (
        <p className="rounded border border-red-500/20 bg-red-500/5 p-2 text-[10px] text-red-500">{error}</p>
      ) : (
        <>
          <div className="flex gap-4 text-[10px] text-[#6B7488]">
            <span><strong className="text-[#475069]">{summary?.connectors.length || 0}</strong> connectors</span>
            <span><strong className="text-[#475069]">{summary?.findings.length || 0}</strong> findings</span>
          </div>
          {summary?.findings.slice(0, 5).map((finding) => (
            <div key={finding.id} className="rounded border border-[#E6E9F0] bg-[#F5F7FA] p-2.5">
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <p className="font-semibold text-[#475069]">{finding.finding}</p>
                  <p className="mt-1 break-all font-mono text-[9px] text-[#6B7488]">{finding.provider}: {finding.resource_id}</p>
                </div>
                <span className="shrink-0 text-[9px] font-bold uppercase text-amber-500">{finding.severity}</span>
              </div>
              <p className="mt-1 text-[10px] text-[#6B7488]">{finding.recommendation}</p>
            </div>
          ))}
          {!summary?.connectors.length && !summary?.findings.length && (
            <p className="text-[10px] italic text-[#6B7488]">No Agent remediation connectors or findings are configured for this tenant.</p>
          )}
        </>
      )}
    </div>
  );
}

export default function AgentPage() {
  const [activePane, setActivePane] = useState<"chat" | "scans">("chat");
  const [workflows, setWorkflows] = useState<Workflow[]>([]);
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [agentRemediation, setAgentRemediation] = useState<AgentRemediationSummary | null>(null);
  const [agentRemediationError, setAgentRemediationError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  // Chat Sessions States
  const [sessions, setSessions] = useState<ChatSession[]>([]);
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
  const [sessionsLoading, setSessionsLoading] = useState(false);

  // Chat States
  const [messages, setMessages] = useState<Message[]>([
    {
      sender: "agent",
      text: "Ask me to check GDPR, HIPAA, or SOC 2 evidence, explain a control, or prepare a remediation plan. I will show evidence before any sensitive action is applied.",
      timestamp: new Date()
    }
  ]);
  const [input, setInput] = useState("");
  const [chatLoading, setChatLoading] = useState(false);
  const [selectedResult, setSelectedResult] = useState<AgentResult | null>(null);
  const [showRawJson, setShowRawJson] = useState(false);
  const [remediating, setRemediating] = useState(false);

  // HITL Approval States
  const [selectedApproval, setSelectedApproval] = useState<Approval | null>(null);
  const [totpCode, setTotpCode] = useState("");
  const [mfaError, setMfaError] = useState<string | null>(null);
  const [approving, setApproving] = useState(false);
  const [showMfaInput, setShowMfaInput] = useState(false);

  const messagesEndRef = useRef<HTMLDivElement>(null);

  const handleRemediate = async (workflowId: string) => {
    if (!workflowId) return;
    setRemediating(true);
    try {
      const res = await fetch(`/api/workflows/${workflowId}/remediate`, {
        method: "POST",
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || "Failed to trigger remediation");
      }

      const updatedWorkflow = await res.json();
      setSelectedResult(updatedWorkflow);
      await fetchWorkflowsAndApprovals();
    } catch (err: unknown) {
      alert(getErrorMessage(err, "Error starting remediation"));
    } finally {
      setRemediating(false);
    }
  };

  const fetchWorkflowsAndApprovals = async () => {
    try {
      const [res, remediationRes] = await Promise.all([
        fetch("/api/workflows"),
        fetch("/api/agent/remediation"),
      ]);
      if (res.status === 401) {
        window.location.href = "/login";
        return;
      }
      if (!res.ok) throw new Error("Failed to load workflows");
      const data = await res.json();
      setWorkflows(data.workflows || []);
      setApprovals(data.approvals || []);
      if (remediationRes.ok) {
        setAgentRemediation(await remediationRes.json());
        setAgentRemediationError(null);
      } else {
        const remediationError = await remediationRes.json().catch(() => ({}));
        setAgentRemediationError(remediationError.error || "Agent remediation service unavailable");
      }
    } catch (err: unknown) {
      console.warn("Agent fetchWorkflowsAndApprovals failed:", getErrorMessage(err, "Unknown error"));
    } finally {
      setLoading(false);
    }
  };

  const fetchSessions = async (autoSelect = false) => {
    setSessionsLoading(true);
    try {
      const res = await fetch("/api/agent/sessions");
      if (!res.ok) throw new Error("Failed to load sessions");
      const data = await res.json();
      setSessions(data || []);
      if (autoSelect && data && data.length > 0) {
        setActiveSessionId(data[0].id);
      }
    } catch (err: unknown) {
      console.warn("fetchSessions failed:", getErrorMessage(err, "Unknown error"));
    } finally {
      setSessionsLoading(false);
    }
  };

  const fetchSessionHistory = async (sessionId: string) => {
    setChatLoading(true);
    try {
      const res = await fetch(`/api/agent/sessions/${sessionId}/history`);
      if (!res.ok) throw new Error("Failed to load message history");
      const data = await res.json();
      if (data && data.length > 0) {
        setMessages((data as ChatHistoryMessage[]).map((m) => ({
          sender: m.sender,
          text: m.text,
          timestamp: new Date(m.timestamp),
          results: m.results
        })));
      } else {
        setMessages([
          {
            sender: "agent",
            text: "Ask me to check GDPR, HIPAA, or SOC 2 evidence, explain a control, or prepare a remediation plan. I will show evidence before any sensitive action is applied.",
            timestamp: new Date()
          }
        ]);
      }
    } catch (err: unknown) {
      console.warn("fetchSessionHistory failed:", getErrorMessage(err, "Unknown error"));
    } finally {
      setChatLoading(false);
    }
  };

  useEffect(() => {
    fetchWorkflowsAndApprovals();
    fetchSessions(true);
    const interval = setInterval(fetchWorkflowsAndApprovals, 5000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (activeSessionId) {
      fetchSessionHistory(activeSessionId);
    }
  }, [activeSessionId]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const createChatSession = async (resetGreeting = false, failureMessage = "Failed to create chat session") => {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 10000);
    const res = await fetch("/api/agent/sessions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: "New Conversation" }),
      signal: controller.signal,
    }).finally(() => window.clearTimeout(timeout));
    if (!res.ok) throw new Error(failureMessage);
    const newSession = await res.json();
    setActiveSessionId(newSession.id);
    setSessions((prev) => [newSession, ...prev]);
    if (resetGreeting) {
      setMessages([
        {
          sender: "agent",
          text: "Ask me to check GDPR, HIPAA, or SOC 2 evidence, explain a control, or prepare a remediation plan. I will show evidence before any sensitive action is applied.",
          timestamp: new Date()
        }
      ]);
    }
    return newSession as ChatSession;
  };

  const handleNewChat = async () => {
    try {
      await createChatSession(true);
    } catch (err: unknown) {
      setMessages((prev) => [
        ...prev,
        {
          sender: "agent",
          text: getErrorMessage(err, "Could not create a saved conversation. You can still ask a one-off question below."),
          timestamp: new Date()
        }
      ]);
    }
  };

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || chatLoading) return;

    let sessionId = activeSessionId;

    let persistentSession = true;
    if (!sessionId) {
      try {
        const newSession = await createChatSession(false, "Failed to auto-create session");
        sessionId = newSession.id;
      } catch (err: unknown) {
        persistentSession = false;
        console.warn("Falling back to stateless agent chat:", getErrorMessage(err, "Could not start saved conversation"));
      }
    }

    const userText = input;
    setInput("");
    setMessages((prev) => [...prev, { sender: "user", text: userText, timestamp: new Date() }]);
    setChatLoading(true);

    try {
      const res = await fetch(persistentSession && sessionId ? `/api/agent/sessions/${sessionId}/message` : "/api/agent/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: userText }),
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.error || "Failed to communicate with Agent");
      }

      const data = await res.json();
      const responseText = data.text || "No response received.";
      const resultsData = data.results || data.workflow || null;
      const newTitle = data.session_title;

      setMessages((prev) => [
        ...prev,
        { sender: "agent", text: responseText, timestamp: new Date(), results: resultsData }
      ]);

      if (resultsData) {
        setSelectedResult(resultsData);
        setShowRawJson(false); // default to visual repor
      }

      if (newTitle) {
        setSessions((prev) =>
          prev.map((s) => (s.id === sessionId ? { ...s, title: newTitle } : s))
        );
      }

      await fetchWorkflowsAndApprovals();
    } catch (err: unknown) {
      setMessages((prev) => [
        ...prev,
        { sender: "agent", text: `Failed to execute request: ${getErrorMessage(err, "Unknown error")}`, timestamp: new Date() }
      ]);
    } finally {
      setChatLoading(false);
    }
  };

  const handleApproveClick = (appr: Approval) => {
    setSelectedApproval(appr);
    setMfaError(null);
    setTotpCode("");
    setShowMfaInput(true);
  };

  const handleMfaSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedApproval) return;
    setApproving(true);
    setMfaError(null);

    try {
      // Find the associated workflow_id
      // In python app/api/v1/endpoints/workflows.py: approve takes workflow_id, not approval_id!
      // So we must lookup the workflow_id for this approval.
      const wf = workflows.find((w) => w.approval_id === selectedApproval.id);
      if (!wf) {
        throw new Error("No active workflow is linked to this approval record");
      }

      const res = await fetch(`/api/workflows/${wf.workflow_id}/approve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ totp_code: totpCode }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "MFA validation failed");
      }

      setShowMfaInput(false);
      setSelectedApproval(null);
      await fetchWorkflowsAndApprovals();
    } catch (err: unknown) {
      setMfaError(getErrorMessage(err, "Could not authorize action"));
    } finally {
      setApproving(false);
    }
  };

  const handleReject = async (appr: Approval) => {
    if (!confirm("Are you sure you want to decline this proposed remediation?")) return;
    try {
      const wf = workflows.find((w) => w.approval_id === appr.id);
      if (!wf) throw new Error("No linked workflow found");

      const res = await fetch(`/api/workflows/${wf.workflow_id}/reject`, {
        method: "POST",
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || "Failed to reject approval");
      }

      await fetchWorkflowsAndApprovals();
    } catch (err: unknown) {
      alert(getErrorMessage(err, "Error rejecting approval"));
    }
  };

  return (
    <div className="ac-page ac-page-agent space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-extrabold tracking-tight text-[#0E1726]">
          Compliance Agent
        </h1>
        <p className="text-[#6B7488] text-sm mt-1">
          Ask compliance questions, review evidence-backed scans, and approve remediation work before it changes anything.
        </p>
      </div>

      {/* Main Grid Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* Left Column (2/3 width) - Chat Interface or Scan Telemetry */}
        <div className="lg:col-span-2 rounded-[20px] border border-[#E6E9F0] bg-white shadow-xl flex flex-col min-h-[620px] overflow-hidden">

          {/* Header tabs */}
          <div className="px-6 py-4 border-b border-[#E6E9F0] bg-[#F5F7FA] flex items-center justify-between">
            <div className="flex gap-4">
              <button
                onClick={() => setActivePane("chat")}
                className={`text-xs font-bold uppercase tracking-wider transition ${
                  activePane === "chat" ? "text-indigo-400" : "text-[#6B7488] hover:text-[#475069]"
                }`}
              >
                Ask Agen
              </button>
              <button
                onClick={() => setActivePane("scans")}
                className={`text-xs font-bold uppercase tracking-wider transition ${
                  activePane === "scans" ? "text-indigo-400" : "text-[#6B7488] hover:text-[#475069]"
                }`}
              >
                Runs
              </button>
            </div>

            {chatLoading && (
              <span className="text-[10px] text-[#6B7488] flex items-center gap-1.5 font-semibold">
                <Loader2 className="w-3.5 h-3.5 animate-spin text-indigo-400" />
                Working...
              </span>
            )}
          </div>

          {/* Chat Pane */}
          {activePane === "chat" ? (
            <div className="flex-1 flex overflow-hidden min-h-[440px]">
              {/* Sessions Sidebar */}
              <div className="w-60 border-r border-[#E6E9F0] bg-[#F5F7FA]/40 flex flex-col justify-between">
                <div className="p-3 border-b border-[#E6E9F0]">
                  <button
                    onClick={handleNewChat}
                    className="w-full flex items-center justify-center gap-1.5 py-2 px-3 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs shadow transition active:scale-[0.98] cursor-pointer"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    New Conversation
                  </button>
                </div>
                <div className="flex-1 overflow-y-auto p-2 space-y-1 max-h-[360px]">
                  {sessionsLoading ? (
                    <div className="flex justify-center py-6">
                      <Loader2 className="w-4 h-4 animate-spin text-indigo-400" />
                    </div>
                  ) : sessions.length === 0 ? (
                    <div className="text-center py-6 text-[#6B7488] text-[10px]">
                      No conversations yet.
                    </div>
                  ) : (
                    sessions.map((s) => (
                      <button
                        key={s.id}
                        onClick={() => setActiveSessionId(s.id)}
                        className={`w-full flex items-center gap-2 py-1.5 px-2.5 rounded-lg text-left text-xs transition cursor-pointer ${
                          activeSessionId === s.id
                            ? "bg-[#F5F7FA]/50 border border-[#E6E9F0] text-indigo-400 font-semibold"
                            : "hover:bg-[#F5F7FA]/50 text-[#6B7488] hover:text-[#0E1726] border border-transparent"
                        }`}
                      >
                        <MessageSquare className="w-3.5 h-3.5 flex-shrink-0" />
                        <span className="truncate">{s.title}</span>
                      </button>
                    ))
                  )}
                </div>
              </div>

              {/* Chat Content */}
              <div className="flex-1 flex flex-col justify-between overflow-hidden">
                {/* Message History */}
                <div className="flex-1 p-6 overflow-y-auto space-y-4 max-h-[370px]">
                  {messages.map((msg, idx) => (
                    <div
                      key={idx}
                      className={`flex gap-3 max-w-[85%] ${
                        msg.sender === "user" ? "ml-auto flex-row-reverse" : ""
                      }`}
                    >
                      <div className={`w-8 h-8 rounded-lg flex-shrink-0 flex items-center justify-center border ${
                        msg.sender === "user"
                          ? "bg-indigo-600/10 border-indigo-500/20 text-indigo-500"
                          : "bg-[#F5F7FA]/40 border-[#E6E9F0] text-[#475069]"
                      }`}>
                        {msg.sender === "user" ? <User className="w-4 h-4" /> : <Bot className="w-4 h-4" />}
                      </div>

                      <div className={`p-3.5 rounded-[20px] text-xs leading-relaxed ${
                        msg.sender === "user"
                          ? "bg-indigo-600 text-white rounded-tr-none"
                          : "bg-[#F5F7FA] border border-[#E6E9F0] text-[#475069] rounded-tl-none"
                      }`}>
                        <pre className="whitespace-pre-wrap font-sans">{msg.text}</pre>
                        {isRagResult(msg.results) && msg.results.citations.length > 0 && (
                          <div className="mt-3 space-y-1.5">
                            <div className="text-[9px] font-bold uppercase tracking-wider text-[#6B7488]">Grounding Evidence</div>
                            {msg.results.citations.slice(0, 3).map((citation: RAGCitation) => (
                              <a
                                key={`${citation.id}-${citation.url}`}
                                href={citation.url}
                                target="_blank"
                                rel="noreferrer"
                                className="flex items-start gap-2 rounded-lg border border-[#E6E9F0] bg-[#F5F7FA]/70 px-2 py-1.5 text-[10px] text-[#475069] hover:border-indigo-500/50 hover:text-indigo-300 transition"
                              >
                                <BookOpen className="mt-0.5 h-3 w-3 flex-shrink-0 text-indigo-400" />
                                <span className="min-w-0 flex-1">
                                  <span className="font-mono font-bold text-[#0E1726]">{citation.id}</span>
                                  <span className="block truncate">{citation.label}</span>
                                </span>
                                <ExternalLink className="mt-0.5 h-3 w-3 flex-shrink-0 text-[#6B7488]" />
                              </a>
                            ))}
                          </div>
                        )}
                        {msg.results && (
                          <button
                            onClick={() => {
                              if (msg.results) setSelectedResult(msg.results);
                            }}
                            className="mt-2 text-[10px] font-bold text-indigo-400 hover:text-indigo-300 flex items-center gap-1 underline transition cursor-pointer"
                          >
                            {isRagResult(msg.results)
                              ? "View Evidence"
                              : isAgentExecutionResult(msg.results)
                                ? "Inspect Agent Trace"
                                : "Inspect Run"}
                          </button>
                        )}
                      </div>
                    </div>
                  ))}
                  <div ref={messagesEndRef} />
                </div>

                {/* Chat Input */}
                <form onSubmit={handleSend} className="p-3 border-t border-[#E6E9F0] bg-[#F5F7FA]/40 flex gap-2">
                  <input
                    type="text"
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    placeholder="Ask about compliance evidence or remediation..."
                    className="flex-1 px-4 py-2.5 rounded-lg bg-[#F5F7FA] border border-[#E6E9F0] text-[#0E1726] text-xs placeholder:text-[#64748b] focus:outline-none focus:border-indigo-500/80 transition"
                    disabled={chatLoading}
                  />
                  <button
                    type="submit"
                    disabled={chatLoading || !input.trim()}
                    className="px-4 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs shadow-lg transition disabled:opacity-50 cursor-pointer"
                  >
                    <Send className="w-3.5 h-3.5" />
                  </button>
                </form>
              </div>
            </div>
          ) : (
            /* Scans Telemetry Pane */
            <div className="flex-1 p-6 overflow-y-auto max-h-[440px] min-h-[440px]">
              {loading ? (
                <div className="flex justify-center py-12">
                  <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-indigo-500" />
                </div>
              ) : workflows.length === 0 ? (
                <div className="space-y-4">
                  <AgentRemediationStatus summary={agentRemediation} error={agentRemediationError} />
                  <div className="text-center py-8 text-[#6B7488] text-xs flex flex-col items-center">
                    <Activity className="w-8 h-8 text-[#6B7488] mb-2" />
                    No control-plane compliance runs yet.
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  <AgentRemediationStatus summary={agentRemediation} error={agentRemediationError} />
                  {workflows.map((wf) => {
                    const isCompleted = wf.execution_status === "COMPLETED";
                    const isPaused = wf.execution_status === "PAUSED";
                    const isSelected = isWorkflowResult(selectedResult) && selectedResult.workflow_id === wf.workflow_id;
                    const remediationActionCount = getRemediationActions(wf).length;
                    return (
                      <button
                        key={wf.id}
                        type="button"
                        onClick={() => {
                          setSelectedResult(wf);
                          setShowRawJson(false);
                        }}
                        className={`w-full text-left p-4 rounded-xl border bg-[#F5F7FA] space-y-3 transition cursor-pointer ${
                          isSelected
                            ? "border-indigo-500/60 shadow-[0_0_0_1px_rgba(99,102,241,0.25)]"
                            : "border-[#E6E9F0] hover:border-[#E6E9F0]"
                        }`}
                      >
                        <div className="flex justify-between items-start">
                          <div>
                            <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                              {wf.framework} framework
                            </span>
                            <h4 className="font-bold text-[#0E1726] text-sm mt-1.5 font-mono">{wf.workflow_id}</h4>
                          </div>

                          <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold ${
                            isCompleted
                              ? "bg-emerald-500/10 border border-emerald-500/20 text-emerald-400"
                              : isPaused
                                ? "bg-amber-500/10 border border-amber-500/20 text-amber-400 animate-pulse"
                                : "bg-sky-500/10 border border-sky-500/20 text-sky-400 animate-pulse"
                          }`}>
                            {wf.execution_status}
                          </span>
                        </div>

                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs pt-2 border-t border-[#E6E9F0]">
                          <div>
                            <p className="text-[#6B7488] text-[10px]">CURRENT STATE</p>
                            <span className="font-mono text-[#475069] font-semibold">{wf.current_state}</span>
                          </div>
                          <div>
                            <p className="text-[#6B7488] text-[10px]">RISK SCORE</p>
                            <span className={`font-semibold ${
                              wf.risk_score && wf.risk_score > 0.5 ? "text-red-400" : "text-emerald-400"
                            }`}>
                              {wf.risk_score !== null ? `${(wf.risk_score * 100).toFixed(0)}%` : "N/A"}
                            </span>
                          </div>
                          <div>
                            <p className="text-[#6B7488] text-[10px]">STARTED AT</p>
                            <span className="text-[#6B7488] font-mono text-[10px]">
                              {new Date(wf.started_at).toLocaleTimeString()}
                            </span>
                          </div>
                          <div>
                            <p className="text-[#6B7488] text-[10px]">COMPLETED</p>
                            <span className="text-[#6B7488] font-mono text-[10px]">
                              {wf.completed_at ? new Date(wf.completed_at).toLocaleTimeString() : "-"}
                            </span>
                          </div>
                        </div>
                        {(wf.remediation_state || remediationActionCount > 0 || wf.error_message) && (
                          <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-[#E6E9F0]">
                            <span className={`px-2 py-0.5 rounded-full border text-[9px] font-black uppercase ${getActionStatusClass(wf.remediation_state || "PENDING")}`}>
                              {formatStateLabel(wf.remediation_state || "NOT_STARTED")}
                            </span>
                            <span className="text-[10px] text-[#6B7488]">
                              {remediationActionCount} action{remediationActionCount === 1 ? "" : "s"}
                            </span>
                            {typeof wf.retry_count === "number" && wf.retry_count > 0 && (
                              <span className="text-[10px] text-amber-400">
                                {wf.retry_count} retr{wf.retry_count === 1 ? "y" : "ies"}
                              </span>
                            )}
                          </div>
                        )}
                      </button>
                    );
                  })}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Right Column (1/3 width) - Pending Approvals (HITL) */}
        <div className="space-y-6">

          {/* HITL panel */}
          <div className="rounded-[20px] border border-[#E6E9F0] bg-white shadow-xl p-5 space-y-4">
            <div>
              <h3 className="text-sm font-bold text-[#0E1726] flex items-center gap-2">
                <ShieldCheck className="w-4.5 h-4.5 text-emerald-400" />
                Approval Queue
              </h3>
              <p className="text-[#6B7488] text-[11px] mt-1 leading-normal">
                Sensitive remediation steps wait here until an administrator approves them.
              </p>
            </div>

            <div className="space-y-4">
              {loading ? (
                <div className="flex justify-center py-6">
                  <div className="animate-spin rounded-full h-6 w-6 border-t-2 border-b-2 border-indigo-500" />
                </div>
              ) : approvals.filter(a => a.status === "PENDING").length === 0 ? (
                <div className="py-6 text-center text-[#6B7488] text-xs flex flex-col items-center">
                  <CheckCircle2 className="w-8 h-8 text-emerald-500 mb-2" />
                  No actions awaiting approval.
                </div>
              ) : (
                approvals.filter(a => a.status === "PENDING").map((appr) => {
                  const destructive = Boolean(appr.action_payload?.plan?.some((item) => item.destructive));
                  const firstTarget = appr.action_payload?.plan?.find((item) => item.target)?.target;
                  return (
                  <div key={appr.id} className="p-3.5 rounded-xl border border-[#E6E9F0] bg-[#F5F7FA] space-y-3 hover:border-[#E6E9F0]/80 transition duration-150">
                    <div>
                      <div className="flex flex-wrap gap-1.5">
                        <span className="text-[9px] uppercase font-black px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
                          {appr.action_type.replace("_", " ")}
                        </span>
                        {destructive && (
                          <span className="text-[9px] uppercase font-black px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20">
                            Fresh MFA required
                          </span>
                        )}
                      </div>
                      <h4 className="font-bold text-[#0E1726] text-xs mt-2">{appr.action_description}</h4>
                      <p className="text-[10px] text-[#6B7488] mt-1">
                        Expires: {new Date(appr.expires_at).toLocaleTimeString()}
                      </p>
                      {firstTarget?.uri && (
                        <p className="font-mono text-[9px] text-[#6B7488] mt-1 break-all">
                          Target: {firstTarget.uri}
                        </p>
                      )}
                    </div>

                    <div className="flex gap-2 pt-1">
                      <button
                        onClick={() => handleApproveClick(appr)}
                        className="flex-1 py-1.5 rounded bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-[10px] shadow transition active:scale-[0.98]"
                      >
                        Approve
                      </button>
                      <button
                        onClick={() => handleReject(appr)}
                        className="flex-1 py-1.5 rounded bg-[#F5F7FA] hover:bg-[#EEF1F6] text-[#475069] border border-[#E6E9F0] text-[10px] font-semibold transition active:scale-[0.98]"
                      >
                        Decline
                      </button>
                    </div>
                  </div>
                  );
                })
              )}
            </div>
          </div>

          {/* Results Details Panel */}
          <div className="rounded-[20px] border border-[#E6E9F0] bg-white shadow-xl p-5 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5 text-[#6B7488] text-xs font-bold uppercase tracking-wider">
                <Terminal className="w-4 h-4 text-indigo-400" />
                Result Inspector
              </div>
              {selectedResult && (
                <button
                  onClick={() => setShowRawJson(!showRawJson)}
                  className="px-2 py-1 text-[9px] font-bold uppercase tracking-wider rounded border border-[#E6E9F0] bg-[#F5F7FA] hover:bg-[#F5F7FA]/80 text-[#6B7488] hover:text-[#0E1726] transition cursor-pointer"
                >
                  {showRawJson ? "Summary" : "Raw Data"}
                </button>
              )}
            </div>

            {isAgentExecutionResult(selectedResult) && !showRawJson ? (
              <div className="space-y-4 text-xs max-h-[450px] overflow-y-auto pr-1">
                <div className="rounded-xl border border-[#E6E9F0] bg-[#F5F7FA] p-3.5 space-y-3">
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-indigo-400">Agent Execution</span>
                    <span className={`rounded-full border px-2 py-0.5 text-[9px] font-bold uppercase ${
                      selectedResult.status === "blocked"
                        ? "border-red-500/20 bg-red-500/10 text-red-400"
                        : selectedResult.status === "approval_required"
                          ? "border-amber-500/20 bg-amber-500/10 text-amber-400"
                          : "border-emerald-500/20 bg-emerald-500/10 text-emerald-400"
                    }`}>
                      {formatStateLabel(selectedResult.status || "completed")}
                    </span>
                  </div>
                  <div className="grid grid-cols-2 gap-3 text-[10px]">
                    <div>
                      <p className="font-bold text-[#6B7488]">REQUEST ID</p>
                      <p className="break-all font-mono text-[#475069]">{selectedResult.request_id}</p>
                    </div>
                    <div>
                      <p className="font-bold text-[#6B7488]">RISK</p>
                      <p className="font-semibold text-[#475069]">{selectedResult.risk_level || "Not reported"}</p>
                    </div>
                    <div>
                      <p className="font-bold text-[#6B7488]">PROVIDER / MODEL</p>
                      <p className="text-[#475069]">{selectedResult.provider || "AuthClaw Gateway"} / {selectedResult.model || "default"}</p>
                    </div>
                    <div>
                      <p className="font-bold text-[#6B7488]">DECISION</p>
                      <p className="text-[#475069]">{selectedResult.decision || selectedResult.reason || "Allowed"}</p>
                    </div>
                  </div>
                  {selectedResult.approval_id && (
                    <div className="rounded border border-amber-500/20 bg-amber-500/10 p-2 text-[10px] text-amber-500">
                      Awaiting human approval: <span className="font-mono">{selectedResult.approval_id}</span>
                    </div>
                  )}
                </div>

                <div className="space-y-2">
                  <div className="text-[10px] font-bold uppercase tracking-wider text-indigo-400">Execution Trace</div>
                  {!selectedResult.trace?.length ? (
                    <div className="rounded-xl border border-[#E6E9F0] bg-[#F5F7FA] p-3 text-center italic text-[#6B7488]">
                      No trace events were returned by the Agent service.
                    </div>
                  ) : (
                    selectedResult.trace.map((event, index) => (
                      <div key={`${event.sequence ?? index}-${event.event ?? "event"}`} className="rounded-xl border border-[#E6E9F0] bg-[#F5F7FA] p-3 space-y-1">
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-semibold text-[#475069]">{event.agent || "Agent"}</span>
                          <span className="font-mono text-[9px] text-indigo-400">{event.event || `step ${index + 1}`}</span>
                        </div>
                        {event.details && <p className="text-[10px] leading-relaxed text-[#6B7488]">{event.details}</p>}
                      </div>
                    ))
                  )}
                </div>
              </div>
            ) : isRagResult(selectedResult) && !showRawJson ? (
              <div className="space-y-4 text-xs max-h-[450px] overflow-y-auto pr-1">
                <div className="p-3.5 rounded-xl border border-[#E6E9F0] bg-[#F5F7FA] space-y-2">
                  <div className="flex justify-between items-center">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-indigo-400">RAG Corpus</span>
                    <span className={`px-2 py-0.5 rounded-full text-[9px] font-bold uppercase border ${
                      selectedResult.grounded
                        ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                        : "bg-amber-500/10 text-amber-400 border-amber-500/20"
                    }`}>
                      {selectedResult.grounded ? "Grounded" : "Insufficient Evidence"}
                    </span>
                  </div>
                  <div className="grid grid-cols-2 gap-2.5 pt-1 text-[11px]">
                    <div>
                      <p className="text-[#6B7488] text-[9px] font-bold">VERSION</p>
                      <p className="font-semibold text-[#475069]">{selectedResult.corpus_version || "-"}</p>
                    </div>
                    <div>
                      <p className="text-[#6B7488] text-[9px] font-bold">CITATIONS</p>
                      <p className="font-semibold text-[#475069]">{selectedResult.citations?.length || 0}</p>
                    </div>
                  </div>
                  {selectedResult.corpus_checksum && (
                    <p className="font-mono text-[9px] text-[#6B7488] truncate">{selectedResult.corpus_checksum}</p>
                  )}
                </div>

                <div className="space-y-2">
                  <div className="text-[10px] font-bold uppercase tracking-wider text-indigo-400">Citations</div>
                  {(!selectedResult.citations || selectedResult.citations.length === 0) ? (
                    <div className="text-[#6B7488] italic p-3 rounded-xl border border-[#E6E9F0] bg-[#F5F7FA] text-center">No matching corpus evidence was retrieved.</div>
                  ) : (
                    <div className="space-y-2">
                      {(selectedResult.citations as RAGCitation[]).map((citation) => (
                        <a
                          key={`${citation.id}-${citation.url}`}
                          href={citation.url}
                          target="_blank"
                          rel="noreferrer"
                          className="block p-3 rounded-xl border border-[#E6E9F0] bg-[#F5F7FA] hover:border-indigo-500/50 transition"
                        >
                          <div className="flex items-start justify-between gap-3">
                            <div className="min-w-0">
                              <p className="font-mono text-[#0E1726] font-bold">{citation.id}</p>
                              <p className="text-[#475069] text-[11px] leading-relaxed">{citation.label}</p>
                              <p className="text-[#6B7488] text-[10px] truncate">{citation.source_name}</p>
                            </div>
                            <ExternalLink className="h-3.5 w-3.5 flex-shrink-0 text-[#6B7488]" />
                          </div>
                        </a>
                      ))}
                    </div>
                  )}
                </div>

                <div className="space-y-2">
                  <div className="text-[10px] font-bold uppercase tracking-wider text-indigo-400">Retrieved Evidence</div>
                  {(selectedResult.retrieved_chunks as RAGChunk[] | undefined)?.map((chunk) => (
                    <div key={`${chunk.id}-${chunk.section_id}`} className="p-3 rounded-xl border border-[#E6E9F0] bg-[#F5F7FA] space-y-1.5">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono text-[10px] font-bold text-[#475069]">{chunk.id}</span>
                        <span className="text-[9px] font-bold text-indigo-400">{chunk.score?.toFixed ? chunk.score.toFixed(2) : chunk.score}</span>
                      </div>
                      <p className="text-[#475069] text-[11px] leading-relaxed">{chunk.text}</p>
                    </div>
                  ))}
                </div>
              </div>
            ) : isWorkflowResult(selectedResult) && !showRawJson ? (
              <div className="space-y-4 text-xs max-h-[450px] overflow-y-auto pr-1">
                {/* Scan Summary */}
                <div className="p-3.5 rounded-xl border border-[#E6E9F0] bg-[#F5F7FA] space-y-2">
                  <div className="flex justify-between items-center">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-indigo-400">Scan Summary</span>
                    <span className={`px-2 py-0.5 rounded-full text-[9px] font-bold uppercase ${
                      selectedResult.execution_status === "COMPLETED"
                        ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                        : selectedResult.execution_status === "PAUSED"
                          ? "bg-amber-500/10 text-amber-400 border border-amber-500/20 animate-pulse"
                          : "bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 animate-pulse"
                    }`}>
                      {selectedResult.execution_status}
                    </span>
                  </div>
                  <div className="grid grid-cols-2 gap-2.5 pt-1 text-[11px]">
                    <div>
                      <p className="text-[#6B7488] text-[9px] font-bold">FRAMEWORK</p>
                      <p className="font-semibold text-[#475069]">{selectedResult.framework}</p>
                    </div>
                    <div>
                      <p className="text-[#6B7488] text-[9px] font-bold">RISK SCORE</p>
                      <p className={`font-semibold ${(selectedResult.risk_score ?? 0) > 0.5 ? "text-red-400" : "text-emerald-400"}`}>
                        {selectedResult.risk_score != null ? `${(selectedResult.risk_score * 100).toFixed(0)}%` : "N/A"}
                      </p>
                    </div>
                    <div>
                      <p className="text-[#6B7488] text-[9px] font-bold">STARTED</p>
                      <p className="text-[#6B7488] font-mono text-[9px]">
                        {selectedResult.started_at ? new Date(selectedResult.started_at).toLocaleTimeString() : "-"}
                      </p>
                    </div>
                    <div>
                      <p className="text-[#6B7488] text-[9px] font-bold">COMPLETED</p>
                      <p className="text-[#6B7488] font-mono text-[9px]">
                        {selectedResult.completed_at ? new Date(selectedResult.completed_at).toLocaleTimeString() : "-"}
                      </p>
                    </div>
                  </div>
                </div>

                {/* Findings List */}
                <div className="space-y-2">
                  <div className="text-[10px] font-bold uppercase tracking-wider text-indigo-400">Findings</div>
                  {(!selectedResult.findings || selectedResult.findings.length === 0) ? (
                    <div className="text-[#6B7488] italic p-3 rounded-xl border border-[#E6E9F0] bg-[#F5F7FA] text-center">No compliance violations found.</div>
                  ) : (
                    <div className="space-y-2">
                      {selectedResult.findings.map((finding: Finding, idx: number) => (
                        <div key={idx} className="p-3 rounded-xl border border-[#E6E9F0] bg-[#F5F7FA] space-y-1.5">
                          <div className="flex justify-between items-center">
                            <span className="font-mono text-[#0E1726] font-bold">{finding.control}</span>
                            <span className={`px-1.5 py-0.5 rounded text-[8px] font-black uppercase ${
                              finding.status === "non_compliant"
                                ? "bg-red-500/10 text-red-400 border border-red-500/20"
                                : "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                            }`}>
                              {finding.status === "non_compliant" ? "NON COMPLIANT" : "COMPLIANT"}
                            </span>
                          </div>
                          <p className="text-[#475069] text-[11px] leading-relaxed">{finding.description}</p>
                          <div className="text-[9px] font-mono text-[#6B7488] leading-normal bg-[#F5F7FA]/30 p-1.5 rounded border border-[#E6E9F0]">
                            <span className="font-bold text-[#6B7488]">Evidence:</span> {finding.evidence}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Remediation Plan */}
                <div className="space-y-2">
                  <div className="text-[10px] font-bold uppercase tracking-wider text-indigo-400">Proposed Remediation Plan</div>
                  {(!selectedResult.remediation_plan || selectedResult.remediation_plan.length === 0) ? (
                    <div className="text-[#6B7488] italic p-3 rounded-xl border border-[#E6E9F0] bg-[#F5F7FA] text-center">No remediation actions needed.</div>
                  ) : (
                    <div className="space-y-2">
                      {selectedResult.remediation_plan.map((plan: RemediationPlan, idx: number) => (
                        <div key={idx} className="p-3 rounded-xl border border-[#E6E9F0] bg-[#F5F7FA] space-y-2">
                          <div className="flex justify-between items-center gap-2">
                            <span className="font-bold text-[#475069]">{plan.action}</span>
                            <div className="flex flex-wrap justify-end gap-1">
                              {plan.destructive && (
                                <span className="px-1.5 py-0.5 rounded text-[8px] font-black uppercase bg-red-500/10 text-red-400 border border-red-500/20">
                                  Destructive
                                </span>
                              )}
                              <span className={`px-1.5 py-0.5 rounded text-[8px] font-black uppercase ${
                                plan.priority === "high"
                                  ? "bg-amber-500/10 text-amber-400 border border-amber-500/20 animate-pulse"
                                  : "bg-blue-500/10 text-blue-400 border border-blue-500/20"
                              }`}>
                                {plan.priority} Priority
                              </span>
                            </div>
                          </div>
                          <div className="grid grid-cols-2 gap-2 text-[10px] text-[#6B7488]">
                            <div>
                              <span className="text-[#6B7488] font-bold">CONTROL:</span> {plan.finding_control}
                            </div>
                            <div>
                              <span className="text-[#6B7488] font-bold">EST. EFFORT:</span> {plan.estimated_effort}
                            </div>
                          </div>
                          {plan.target?.uri && (
                            <div className="rounded border border-[#E6E9F0] bg-white p-2 font-mono text-[9px] text-[#6B7488] break-all">
                              Target: {plan.target.uri}
                            </div>
                          )}
                          {plan.diff?.preview && plan.diff.preview.length > 0 && (
                            <div className="rounded border border-[#E6E9F0] bg-white p-2 font-mono text-[9px] leading-relaxed text-[#6B7488] whitespace-pre-wrap">
                              {plan.diff.preview.join("\n")}
                            </div>
                          )}
                          {plan.diff?.commands && plan.diff.commands.length > 0 && (
                            <div className="rounded border border-[#E6E9F0] bg-white p-2 font-mono text-[9px] leading-relaxed text-[#6B7488] whitespace-pre-wrap">
                              {plan.diff.commands.slice(0, 3).join("\n")}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Remediation Timeline */}
                <div className="space-y-2">
                  <div className="text-[10px] font-bold uppercase tracking-wider text-indigo-400">Remediation Timeline</div>
                  <div className="p-3 rounded-xl border border-[#E6E9F0] bg-[#F5F7FA] space-y-2.5">
                    <RemediationTimeline workflow={selectedResult} />
                  </div>
                </div>

                {/* Apply Remediation Button (Explicit Workflow ID) */}
                {selectedResult.execution_status === "COMPLETED" && selectedResult.current_state === "COMPLETE" && (selectedResult.remediation_plan?.length ?? 0) > 0 && (
                  <button
                    onClick={() => handleRemediate(selectedResult.workflow_id || "")}
                    disabled={remediating}
                    className="w-full py-2 px-4 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs shadow-lg transition active:scale-[0.98] disabled:opacity-50 mt-4 flex items-center justify-center gap-1.5 cursor-pointer"
                  >
                    {remediating ? (
                      <>
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        Initializing Remediation...
                      </>
                    ) : (
                      "Apply Remediation"
                    )}
                  </button>
                )}
              </div>
            ) : (
              <div className="rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] p-3 text-[10px] font-mono text-[#6B7488] overflow-x-auto min-h-[140px] max-h-[350px]">
                {selectedResult ? (
                  <pre>{JSON.stringify(selectedResult, null, 2)}</pre>
                ) : (
                  <div className="h-full flex items-center justify-center text-[#6B7488] text-center italic py-12">
                    Select a message result or run to inspect evidence, findings, and remediation status.
                  </div>
                )}
              </div>
            )}
          </div>

        </div>

      </div>

      {/* MFA TOTP Challenge Modal */}
      {showMfaInput && (
        <MfaChallengeModal
          code={totpCode}
          setCode={setTotpCode}
          busy={approving}
          error={mfaError}
          onClose={() => setShowMfaInput(false)}
          onSubmit={handleMfaSubmit}
          description="Confirm your administrator status. Enter the 6-digit TOTP code from your authenticator app (or backup recovery code)."
          submitLabel="Authorize Action"
          requireCode
        />
      )}
    </div>
  );
}
