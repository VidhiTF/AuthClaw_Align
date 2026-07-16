import { agentJson, agentRouteError, createAgentSession, listAgentSessions } from "@/lib/agent-client";

export async function GET() {
  try {
    return agentJson(await listAgentSessions());
  } catch (error: unknown) {
    return agentRouteError(error);
  }
}

export async function POST(request: Request) {
  try {
    const body = await request.json().catch(() => ({}));
    return agentJson(await createAgentSession(body.title), 201);
  } catch (error: unknown) {
    return agentRouteError(error);
  }
}
