import { randomUUID } from "crypto";
import { NextResponse } from "next/server";
import { agentFetch, handleApiError } from "./api-client";

type AgentMessage = {
  role?: string;
  sender?: string;
  content?: string;
  text?: string;
  timestamp?: string;
  trace?: unknown;
};

export async function listAgentSessions() {
  const sessions = await agentFetch("/chat/sessions");
  return (Array.isArray(sessions) ? sessions : []).map((session) => ({
    id: session.session_id,
    title: session.title || "New Conversation",
  }));
}

export async function createAgentSession(title = "New Conversation") {
  const sessionId = randomUUID();
  const session = await agentFetch("/chat/sessions", {
    method: "POST",
    body: JSON.stringify({ session_id: sessionId, title }),
  });
  return { id: session.session_id, title: session.title || title };
}

export async function getAgentHistory(sessionId: string) {
  const history = await agentFetch(`/chat/sessions/${encodeURIComponent(sessionId)}`);
  return (Array.isArray(history) ? history : []).map((message: AgentMessage) => ({
    sender: message.sender === "user" || message.role === "user" ? "user" : "agent",
    text: message.text || message.content || "",
    timestamp: message.timestamp || new Date().toISOString(),
    ...(message.trace === undefined ? {} : { results: { trace: message.trace } }),
  }));
}

export async function sendAgentMessage(sessionId: string, message: string) {
  const result = await agentFetch("/chat", {
    method: "POST",
    body: JSON.stringify({ session_id: sessionId, message }),
  });
  const text = result.response || result.message || (
    result.status === "approval_required"
      ? `This action requires approval (${result.approval_id || "pending"}).`
      : result.status === "blocked"
        ? `Request blocked by policy (${result.category || result.reason || "policy violation"}).`
        : "No response received."
  );
  return { text, results: result };
}

export function agentRouteError(error: unknown) {
  return handleApiError(error);
}

export function agentJson(data: unknown, status = 200) {
  return NextResponse.json(data, { status });
}
