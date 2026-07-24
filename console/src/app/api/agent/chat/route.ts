import { agentJson, agentRouteError, createAgentSession, sendAgentMessage } from "@/lib/agent-client";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    if (!body.message?.trim()) return agentJson({ error: "Message is required" }, 400);
    const session = await createAgentSession();
    return agentJson(await sendAgentMessage(session.id, body.message));
  } catch (error: unknown) {
    return agentRouteError(error);
  }
}
