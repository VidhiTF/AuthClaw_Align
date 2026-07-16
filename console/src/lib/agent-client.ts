import { randomUUID } from "crypto";
import { NextResponse } from "next/server";
import { agentFetch, backendFetch, handleApiError } from "./api-client";

type AgentMessage = {
  role?: string;
  sender?: string;
  content?: string;
  text?: string;
  timestamp?: string;
  trace?: unknown;
};

type ProviderCredential = {
  provider?: string;
  status?: string;
};

type GatewayConfig = {
  provider?: string;
  is_active?: boolean;
  model_whitelist?: string[] | null;
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
  return (Array.isArray(history) ? history : []).map((message: AgentMessage) => {
    const trace = Array.isArray(message.trace) ? message.trace : [];
    const requestId = trace.find((event) => event && typeof event === "object" && "request_id" in event)?.request_id;
    return {
      sender: message.sender === "user" || message.role === "user" ? "user" : "agent",
      text: message.text || message.content || "",
      timestamp: message.timestamp || new Date().toISOString(),
      ...(message.trace === undefined ? {} : { results: { request_id: String(requestId || "history"), trace } }),
    };
  });
}

export async function sendAgentMessage(sessionId: string, message: string) {
  const [credentials, gateways] = await Promise.all([
    backendFetch("/v1/provider-credentials"),
    backendFetch("/v1/gateways"),
  ]);
  const activeCredentials = (Array.isArray(credentials) ? credentials : []).filter(
    (item: ProviderCredential) => item.status === "active" && item.provider,
  );
  const activeGateway = (Array.isArray(gateways) ? gateways : []).find(
    (item: GatewayConfig) => item.is_active && activeCredentials.some(
      (credential: ProviderCredential) => credential.provider === item.provider,
    ),
  ) as GatewayConfig | undefined;
  const credential = activeGateway
    ? activeCredentials.find((item: ProviderCredential) => item.provider === activeGateway.provider)
    : activeCredentials.length === 1 ? activeCredentials[0] : undefined;
  if (!credential?.provider) {
    throw new Error("Configure one active gateway route with a matching provider key before asking the Agent.");
  }
  const result = await agentFetch("/chat", {
    method: "POST",
    body: JSON.stringify({
      session_id: sessionId,
      message,
      provider: credential.provider,
      model: activeGateway?.model_whitelist?.[0],
    }),
    forwardGatewayKey: true,
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
