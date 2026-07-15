import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { queryWithTenantContext } from "@/lib/db";
import { backendFetch, handleApiError, proxyBackendJson } from "@/lib/api-client";

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const id = searchParams.get("id");

    if (id) {
      const cookieStore = await cookies();
      const sessionToken = cookieStore.get("authclaw_session")?.value;
      if (!sessionToken) {
        return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
      }
      const payload = JSON.parse(sessionToken);
      const tenantId = payload.tenantId;

      const res = await queryWithTenantContext(
        tenantId,
        "SELECT id, name, description, policy_yaml, version, is_active, created_at FROM policies WHERE tenant_id = $1 AND id = $2",
        [tenantId, id]
      );
      if (res.rowCount === 0) {
        return NextResponse.json({ error: "Policy not found" }, { status: 404 });
      }
      return NextResponse.json(res.rows[0]);
    }

    const data = await backendFetch("/v1/policies");
    return NextResponse.json(data);
  } catch (error: unknown) {
    return handleApiError(error);
  }
}

export async function POST(request: Request) {
  return proxyBackendJson(request, "/v1/policies", "POST", 201);
}
