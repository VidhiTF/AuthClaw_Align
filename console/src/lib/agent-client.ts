import { NextResponse } from "next/server";
import { backendFetch, handleApiError } from "./api-client";

type AgentMessage = {
  role?: string;
  sender?: string;
  content?: string;
  text?: string;
  timestamp?: string;
  trace?: unknown;
  results?: unknown;
};

export async function listAgentSessions() {
  const sessions = await backendFetch("/v1/chat/sessions");
  return (Array.isArray(sessions) ? sessions : []).map((session) => ({
    id: session.id,
    title: session.title || "New Conversation",
  }));
}

export async function createAgentSession(title = "New Conversation") {
  const session = await backendFetch("/v1/chat/sessions", {
    method: "POST",
    body: JSON.stringify({ title }),
  });
  return { id: session.id, title: session.title || title };
}

export async function getAgentHistory(sessionId: string) {
  const history = await backendFetch(`/v1/chat/sessions/${encodeURIComponent(sessionId)}/history`);
  return (Array.isArray(history) ? history : []).map((message: AgentMessage) => {
    const trace = Array.isArray(message.trace) ? message.trace : [];
    const requestId = trace.find((event) => event && typeof event === "object" && "request_id" in event)?.request_id;
    return {
      sender: message.sender === "user" || message.role === "user" ? "user" : "agent",
      text: message.text || message.content || "",
      timestamp: message.timestamp || new Date().toISOString(),
      ...(message.results !== undefined
        ? { results: message.results }
        : message.trace === undefined
          ? {}
          : { results: { request_id: String(requestId || "history"), trace } }),
    };
  });
}

export async function sendAgentMessage(sessionId: string, message: string) {
  return backendFetch(`/v1/chat/sessions/${encodeURIComponent(sessionId)}/message`, {
    method: "POST",
    body: JSON.stringify({ message }),
  });
}

export function agentRouteError(error: unknown) {
  return handleApiError(error);
}

export function agentJson(data: unknown, status = 200) {
  return NextResponse.json(data, { status });
}
