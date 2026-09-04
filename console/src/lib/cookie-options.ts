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
