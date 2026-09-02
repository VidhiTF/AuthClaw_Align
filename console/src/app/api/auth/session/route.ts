import { NextResponse } from "next/server";
import { cookies } from "next/headers";

export async function GET() {
  try {
    const cookieStore = await cookies();
    const sessionToken = cookieStore.get("authclaw_session")?.value;
    if (!sessionToken) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }
    const backend = await fetch(
      `${process.env.API_URL || "http://localhost:8000"}/v1/auth/me`,
      { headers: { Authorization: `Bearer ${sessionToken}` }, cache: "no-store" },
    );
    if (!backend.ok) {
      const response = NextResponse.json({ error: "Unauthorized: Session expired or invalid" }, { status: 401 });
      response.cookies.delete("authclaw_session");
      return response;
    }
    const principal = await backend.json();
    return NextResponse.json({
      userId: principal.id,
      tenantId: principal.tenant_id,
      email: principal.email,
      role: principal.role,
      scopes: ["read", "write", "admin"],
    });
  } catch {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
}
