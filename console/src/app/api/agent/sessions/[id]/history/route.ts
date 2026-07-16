import { agentJson, agentRouteError, getAgentHistory } from "@/lib/agent-client";
import { routeParam, RouteContext } from "@/lib/api-client";

export async function GET(_request: Request, context: RouteContext) {
  try {
    return agentJson(await getAgentHistory(await routeParam(context, "id")));
  } catch (error: unknown) {
    return agentRouteError(error);
  }
}
