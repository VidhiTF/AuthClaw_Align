import { agentFetch, handleApiError, routeParam, RouteContext } from "@/lib/api-client";
import { NextResponse } from "next/server";

type ApprovalActionContext = RouteContext<{ id: string; action: string }>;

export async function POST(request: Request, context: ApprovalActionContext) {
  try {
    const approvalId = await routeParam(context, "id");
    const action = await routeParam(context, "action");
    if (!/^[A-Za-z0-9._:-]+$/.test(approvalId) || !["approve", "execute"].includes(action)) {
      return NextResponse.json({ error: "Not found" }, { status: 404 });
    }
    const body = await request.json();
    const result = await agentFetch(`/${action}/${approvalId}`, {
      method: "POST",
      body: JSON.stringify(body),
    });
    return NextResponse.json(result);
  } catch (error: unknown) {
    return handleApiError(error);
  }
}
