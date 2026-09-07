import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { oidcStateCookieName, sessionCookieName, sessionCookieOptions } from "@/lib/cookie-options";
import { openOidcState } from "@/lib/oidc-state";
import { oidcServiceHeaders } from "@/lib/oidc-service";

const BACKEND_URL = process.env.API_URL || "http://localhost:8000";
const GENERIC_AUTH_FAILURE = "Authentication failed";

export async function GET(request: Request) {
  const url = new URL(request.url);
  const requestId = request.headers.get("x-request-id") || "";
  const cookieStore = await cookies();
  const stateCookie = cookieStore.get(oidcStateCookieName())?.value;
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
    response.cookies.delete(oidcStateCookieName());
    return response;
  };

  if (url.searchParams.get("error")) {
    return fail(GENERIC_AUTH_FAILURE);
  }
  if (!stateCookie) {
    auditStateFailure();
    return fail("SSO state expired. Try again.");
  }

  let expected: string;
  try {
    expected = openOidcState(stateCookie);
  } catch {
    auditStateFailure();
    return fail("Invalid SSO state");
  }
  const code = url.searchParams.get("code") || "";
  const state = url.searchParams.get("state") || "";
  if (!code || state !== expected || url.searchParams.getAll("state").length !== 1 || url.searchParams.getAll("code").length !== 1) {
    auditStateFailure();
    return fail("Invalid SSO callback state");
  }
  try {
    // Backend atomically consumes the server-owned record before token exchange.
    const body = JSON.stringify({ code, transaction_id: expected });
    const backendResponse = await fetch(`${BACKEND_URL}/v1/auth/oidc/callback`, {
      method: "POST",
      headers: oidcServiceHeaders("/v1/auth/oidc/callback", body),
      body,
    });
    const data = await backendResponse.json().catch(() => ({}));
    if (!backendResponse.ok) {
      return fail(GENERIC_AUTH_FAILURE);
    }

    const response = NextResponse.redirect(`${url.origin}/overview`);
    response.cookies.set(sessionCookieName(), data.session_token, {
      ...sessionCookieOptions(60 * 60 * 24),
    });
    response.cookies.delete(oidcStateCookieName());
    return response;
  } catch {
    return fail(GENERIC_AUTH_FAILURE);
  }
}
