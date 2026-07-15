import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { sessionCookieOptions } from "@/lib/cookie-options";
import { sessionStore } from "@/lib/session-store";

const BACKEND_URL = process.env.API_URL || "http://localhost:8000";

export async function GET(request: Request) {
  const url = new URL(request.url);
  const cookieStore = await cookies();
  const stateCookie = cookieStore.get("authclaw_oidc_state")?.value;
  const fail = (message: string) => {
    const response = NextResponse.redirect(`${url.origin}/login?sso_error=${encodeURIComponent(message)}`);
    response.cookies.delete("authclaw_oidc_state");
    return response;
  };

  if (url.searchParams.get("error")) {
    return fail(url.searchParams.get("error_description") || url.searchParams.get("error") || "SSO failed");
  }
  if (!stateCookie) return fail("SSO state expired. Try again.");

  let expected: { state: string; nonce: string; tenantName: string; redirectUri: string };
  try {
    expected = JSON.parse(stateCookie);
  } catch {
    return fail("Invalid SSO state");
  }
  const code = url.searchParams.get("code") || "";
  const state = url.searchParams.get("state") || "";
  if (!code || state !== expected.state) return fail("Invalid SSO callback state");

  const backendResponse = await fetch(`${BACKEND_URL}/v1/auth/oidc/callback`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      code,
      state,
      nonce: expected.nonce,
      tenant_name: expected.tenantName || null,
      redirect_uri: expected.redirectUri,
    }),
  });
  const data = await backendResponse.json().catch(() => ({}));
  if (!backendResponse.ok) {
    return fail(data.detail || data.message || "SSO callback failed");
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
  const response = NextResponse.redirect(`${url.origin}/overview`);
  response.cookies.set("authclaw_session", JSON.stringify(cookiePayload), {
    ...sessionCookieOptions(60 * 60 * 24),
  });
  response.cookies.delete("authclaw_oidc_state");
  return response;
}
