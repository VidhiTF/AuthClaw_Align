import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { sessionCookieOptions } from "@/lib/cookie-options";
import { sessionStore } from "@/lib/session-store";
import { consumeOidcState, openOidcState, type OidcState } from "@/lib/oidc-state";

const BACKEND_URL = process.env.API_URL || "http://localhost:8000";
const GENERIC_AUTH_FAILURE = "Authentication failed";

export async function GET(request: Request) {
  const url = new URL(request.url);
  const requestId = request.headers.get("x-request-id") || "";
  const cookieStore = await cookies();
  const stateCookie = cookieStore.get("authclaw_oidc_state")?.value;
  const auditStateFailure = () => console.warn(JSON.stringify({
    tenant_id: "",
    actor_id: "",
    action: "auth:state_validation_failed",
    result: "failure",
    reason: "state_validation_failed",
    request_correlation_id: requestId,
  }));
  const fail = (message: string) => {
    const response = NextResponse.redirect(`${url.origin}/login?sso_error=${encodeURIComponent(message)}`);
    response.cookies.delete("authclaw_oidc_state");
    return response;
  };

  if (url.searchParams.get("error")) {
    return fail(GENERIC_AUTH_FAILURE);
  }
  if (!stateCookie) {
    auditStateFailure();
    return fail("SSO state expired. Try again.");
  }

  let expected: OidcState;
  try {
    expected = openOidcState(stateCookie);
  } catch {
    auditStateFailure();
    return fail("Invalid SSO state");
  }
  const code = url.searchParams.get("code") || "";
  const state = url.searchParams.get("state") || "";
  if (!code || state !== expected.state) {
    auditStateFailure();
    return fail("Invalid SSO callback state");
  }
  try {
    consumeOidcState(stateCookie);
  } catch {
    auditStateFailure();
    return fail("Invalid SSO state");
  }

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
    return fail(GENERIC_AUTH_FAILURE);
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
