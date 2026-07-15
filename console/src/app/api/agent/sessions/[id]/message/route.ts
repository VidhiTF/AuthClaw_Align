import { agentJson, agentRouteError, sendAgentMessage } from "@/lib/agent-client";
import { routeParam, RouteContext } from "@/lib/api-client";

export async function POST(request: Request, context: RouteContext) {
  try {
    const body = await request.json();
    if (!body.message?.trim()) return agentJson({ error: "Message is required" }, 400);
    return agentJson(await sendAgentMessage(await routeParam(context, "id"), body.message));
  } catch (error: unknown) {
    return agentRouteError(error);
  }
}
