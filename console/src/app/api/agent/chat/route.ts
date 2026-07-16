import { randomUUID } from "crypto";
import { agentJson, agentRouteError, sendAgentMessage } from "@/lib/agent-client";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    if (!body.message?.trim()) return agentJson({ error: "Message is required" }, 400);
    return agentJson(await sendAgentMessage(randomUUID(), body.message));
  } catch (error: unknown) {
    return agentRouteError(error);
  }
}
