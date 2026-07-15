import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { queryWithTenantContext } from "@/lib/db";
import { handleApiError, proxyBackendJson } from "@/lib/api-client";
import { sessionStore } from "@/lib/session-store";

type WorkflowRow = {
  state_data?: {
    remediation_state?: string;
    remediation_actions?: unknown[];
    rollback_result?: unknown;
  } | null;
  execution_result?: {
    remediation_state?: string;
    actions?: unknown[];
  } | null;
  [key: string]: unknown;
};

export async function GET() {
  try {
    const cookieStore = await cookies();
    const sessionToken = cookieStore.get("authclaw_session")?.value;
    if (!sessionToken) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const payload = JSON.parse(sessionToken);
    const session = sessionStore.getSession(payload.sessionId);
    if (!session) {
      const response = NextResponse.json({ error: "Unauthorized: Session expired or invalid" }, { status: 401 });
      response.cookies.delete("authclaw_session");
      return response;
    }

    const tenantId = payload.tenantId;

    // Fetch compliance workflows
    const workflowsRes = await queryWithTenantContext(
      tenantId,
      `SELECT id, workflow_id, framework, current_state, execution_status, risk_score,
              findings, remediation_plan, execution_result, error_message, retry_count,
              state_data, started_at, completed_at, approval_id
       FROM compliance_workflows
       WHERE tenant_id = $1
       ORDER BY started_at DESC
       LIMIT 50`,
      [tenantId]
    );

    // Fetch pending approvals
    const approvalsRes = await queryWithTenantContext(
      tenantId,
      "SELECT id, action_id, action_type, action_description, action_payload, status, expires_at, created_at FROM pending_approvals WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 50",
      [tenantId]
    );

    const workflows = workflowsRes.rows.map((workflow: WorkflowRow) => {
      const stateData = workflow.state_data || {};
      const executionResult = workflow.execution_result || {};
      return {
        ...workflow,
        remediation_state: stateData.remediation_state || executionResult.remediation_state || null,
        remediation_actions: stateData.remediation_actions || executionResult.actions || [],
        rollback_result: stateData.rollback_result || null,
      };
    });

    return NextResponse.json({
      workflows,
      approvals: approvalsRes.rows,
    });
  } catch (error: unknown) {
    return handleApiError(error);
  }
}

export async function POST(request: Request) {
  return proxyBackendJson(request, "/v1/workflows", "POST", 201);
}
