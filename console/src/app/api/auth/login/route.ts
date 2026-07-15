import { NextResponse } from "next/server";
import { sessionStore } from "@/lib/session-store";
import { sessionCookieOptions } from "@/lib/cookie-options";

const BACKEND_URL = process.env.API_URL || "http://localhost:8000";

export async function POST(request: Request) {
  try {
    const { email, password, tenantName, tenant_name } = await request.json();
    const rawTenantName = tenantName ?? tenant_name;
    const cleanTenantName = typeof rawTenantName === "string" ? rawTenantName.trim() || null : null;

    if (!email || !password) {
      return NextResponse.json(
        { message: "Email and password are required" },
        { status: 400 }
      );
    }

    const backendResponse = await fetch(`${BACKEND_URL}/v1/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password, tenant_name: cleanTenantName }),
    });
    const data = await backendResponse.json();
    if (!backendResponse.ok) {
      return NextResponse.json(
        { message: data.detail || data.message || "Authentication failed" },
        { status: backendResponse.status }
      );
    }

    const session = sessionStore.createSession({
      apiKey: data.api_key,
      userId: data.user_id,
      tenantId: data.tenant_id,
      scopes: data.scopes,
      role: data.role,
    });

    const cookiePayload = {
      sessionId: session.sessionId,
      userId: data.user_id,
      tenantId: data.tenant_id,
      tenantName: data.tenant_name,
      scopes: data.scopes,
      role: data.role,
      email: data.email,
    };

    const response = NextResponse.json({ success: true, user: cookiePayload });

    response.cookies.set("authclaw_session", JSON.stringify(cookiePayload), {
      ...sessionCookieOptions(60 * 60 * 24),
    });

    return response;
  } catch (error: unknown) {
    console.error("Login API Error:", error);
    return NextResponse.json(
      { message: `Internal server error during login: ${(error instanceof Error ? error.message : "Request failed")}` },
      { status: 500 }
    );
  }
}
