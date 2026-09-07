import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { sessionCookieName } from "@/lib/cookie-options";

export async function GET() {
  try {
    const cookieStore = await cookies();
    const sessionToken = cookieStore.get(sessionCookieName())?.value;
    if (!sessionToken) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }
    const backend = await fetch(
      `${process.env.API_URL || "http://localhost:8000"}/v1/auth/me`,
      { headers: { Authorization: `Bearer ${sessionToken}` }, cache: "no-store" },
    );
    if (!backend.ok) {
      const response = NextResponse.json({ error: "Unauthorized: Session expired or invalid" }, { status: 401 });
      response.cookies.delete(sessionCookieName());
      return response;
    }
    const principal = await backend.json();
    return NextResponse.json({
      userId: principal.id,
      tenantId: principal.tenant_id,
      email: principal.email,
      role: principal.role,
      platformRole: principal.platform_role || "NONE",
      scopes: Array.isArray(principal.scopes) ? principal.scopes : [],
    });
  } catch {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
}
