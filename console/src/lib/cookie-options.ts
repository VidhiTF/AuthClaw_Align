export function sessionCookieOptions(maxAge?: number) {
  const secure = process.env.AUTHCLAW_COOKIE_SECURE === "true";
  return {
    httpOnly: true,
    secure,
    sameSite: "lax" as const,
    ...(maxAge ? { maxAge } : {}),
    path: "/",
  };
}
