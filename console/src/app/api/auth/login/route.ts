import { NextResponse } from "next/server";
import { sessionCookieName, sessionCookieOptions } from "@/lib/cookie-options";
import { bffClientIPHeaders } from "@/lib/bff-client-ip";

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

    const body = JSON.stringify({ email, password, tenant_name: cleanTenantName });
    const backendResponse = await fetch(`${BACKEND_URL}/v1/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...bffClientIPHeaders(request, body) },
      body,
    });
    const data = await backendResponse.json();
    if (!backendResponse.ok) {
      return NextResponse.json(
        { message: data.detail || data.message || "Authentication failed" },
        { status: backendResponse.status }
      );
    }

    const user = {
      userId: data.user_id,
      tenantId: data.tenant_id,
      tenantName: data.tenant_name,
      scopes: data.scopes,
      role: data.role,
      email: data.email,
    };
    const response = NextResponse.json({ success: true, user });

    response.cookies.set(sessionCookieName(), data.session_token, {
      ...sessionCookieOptions(60 * 60 * 24),
    });

    return response;
  } catch (error: unknown) {
    console.error("Login API Error:", error);
    return NextResponse.json(
      { message: "Authentication failed" },
      { status: 500 }
    );
  }
}
