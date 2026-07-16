import { sessionStore, type SessionData } from "./session-store.ts";

export function authenticateSessionCookie(
  value: string | undefined,
  store: Pick<typeof sessionStore, "getSession"> = sessionStore
): SessionData | undefined {
  if (!value) return undefined;
  try {
    const payload = JSON.parse(value);
    const allowed = new Set(["sessionId", "userId", "tenantId", "tenantName", "scopes", "role", "email"]);
    if (Object.keys(payload).some((key) => !allowed.has(key))) return undefined;
    const session = store.getSession(payload.sessionId);
    if (!session) return undefined;
    if (
      payload.userId !== session.userId ||
      payload.tenantId !== session.tenantId ||
      payload.role !== session.role ||
      JSON.stringify(payload.scopes) !== JSON.stringify(session.scopes)
    ) return undefined;
    return session;
  } catch {
    return undefined;
  }
}
