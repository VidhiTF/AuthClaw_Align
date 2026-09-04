import { randomBytes } from "crypto";
import { NextResponse } from "next/server";
import { sessionCookieOptions } from "@/lib/cookie-options";
import { sealOidcState } from "@/lib/oidc-state";
import { oidcServiceHeaders } from "@/lib/oidc-service";

const BACKEND_URL = process.env.API_URL || "http://localhost:8000";

export async function GET(request: Request) {
  const { searchParams, origin } = new URL(request.url);
  if (process.env.AUTHCLAW_OIDC_LOGIN_PAUSED === "true") {
    return NextResponse.redirect(`${origin}/login?sso_error=SSO%20temporarily%20paused`);
  }
  try {
  const tenantName = searchParams.get("tenantName") || searchParams.get("tenant_name") || "";
  const state = randomBytes(32).toString("base64url");
  const body = JSON.stringify({ transaction_id: state, tenant_name: tenantName || null });

  const backendResponse = await fetch(`${BACKEND_URL}/v1/auth/oidc/start`, {
    method: "POST", headers: oidcServiceHeaders("/v1/auth/oidc/start", body), body,
  });
  const data = await backendResponse.json().catch(() => ({}));
  if (!backendResponse.ok || !data.enabled || !data.authorization_url) {
    const reason = encodeURIComponent("SSO is not configured or temporarily unavailable");
    return NextResponse.redirect(`${origin}/login?sso_error=${reason}`);
  }

  const response = NextResponse.redirect(data.authorization_url);
  const sealedState = sealOidcState(state);
  response.cookies.set("authclaw_oidc_state", sealedState, {
    ...sessionCookieOptions(600),
    httpOnly: true,
  });
  return response;
  } catch {
    return NextResponse.redirect(`${origin}/login?sso_error=Authentication%20failed`);
  }
}
