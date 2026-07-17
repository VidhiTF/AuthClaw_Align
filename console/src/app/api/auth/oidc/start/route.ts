import { randomBytes } from "crypto";
import { NextResponse } from "next/server";
import { sessionCookieOptions } from "@/lib/cookie-options";
import { registerOidcState, sealOidcState } from "@/lib/oidc-state";

const BACKEND_URL = process.env.API_URL || "http://localhost:8000";

export async function GET(request: Request) {
  const { searchParams, origin } = new URL(request.url);
  const tenantName = searchParams.get("tenantName") || searchParams.get("tenant_name") || "";
  const state = randomBytes(24).toString("base64url");
  const nonce = randomBytes(24).toString("base64url");
  const params = new URLSearchParams({ state, nonce });
  if (tenantName) params.set("tenant_name", tenantName);

  const backendResponse = await fetch(`${BACKEND_URL}/v1/auth/oidc/start?${params.toString()}`);
  const data = await backendResponse.json().catch(() => ({}));
  if (!backendResponse.ok || !data.enabled || !data.authorization_url) {
    const reason = encodeURIComponent(data.detail || data.error || "SSO is not configured");
    return NextResponse.redirect(`${origin}/login?sso_error=${reason}`);
  }

  const response = NextResponse.redirect(data.authorization_url);
  const sealedState = sealOidcState({
    state,
    nonce,
    tenantName,
    redirectUri: data.redirect_uri,
    issuedAt: Date.now(),
  });
  registerOidcState(sealedState);
  response.cookies.set("authclaw_oidc_state", sealedState, {
    ...sessionCookieOptions(600),
    httpOnly: true,
  });
  return response;
}
