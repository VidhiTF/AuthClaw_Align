import { NextResponse } from "next/server";
import { sessionStore } from "@/lib/session-store";
import { sessionCookieOptions } from "@/lib/cookie-options";

const BACKEND_URL = process.env.API_URL || "http://localhost:8000";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const response = await fetch(`${BACKEND_URL}/v1/onboarding/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await response.json();

    if (!response.ok) {
      return NextResponse.json(data, { status: response.status });
    }

    const session = sessionStore.createSession({
      apiKey: data.api_key,
      userId: data.user_id,
      tenantId: data.tenant_id,
      scopes: ["admin", "read", "write"],
      role: data.role || "owner",
    });

    const cookiePayload = {
      sessionId: session.sessionId,
      userId: data.user_id,
      tenantId: data.tenant_id,
      tenantName: data.tenant_name,
      scopes: ["admin", "read", "write"],
      role: data.role || "owner",
      email: data.email,
    };

    const nextResponse = NextResponse.json(data);
    nextResponse.cookies.set("authclaw_session", JSON.stringify(cookiePayload), {
      ...sessionCookieOptions(60 * 60 * 24),
    });
    return nextResponse;
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Onboarding verification failed";
    return NextResponse.json({ detail: message }, { status: 500 });
  }
}
