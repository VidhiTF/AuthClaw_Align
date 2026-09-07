export function sessionCookieOptions(maxAge?: number) {
  const secure = process.env.AUTHCLAW_COOKIE_SECURE
    ? process.env.AUTHCLAW_COOKIE_SECURE === "true"
    : process.env.NODE_ENV === "production";
  return {
    httpOnly: true,
    secure,
    sameSite: "lax" as const,
    ...(maxAge ? { maxAge } : {}),
    path: "/",
  };
}

export function sessionCookieName() {
  return process.env.AUTHCLAW_SESSION_COOKIE_NAME || "authclaw_session";
}

export function oidcStateCookieName() {
  return process.env.AUTHCLAW_OIDC_STATE_COOKIE_NAME || "authclaw_oidc_state";
}
