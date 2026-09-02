export function sessionKeyRing(): { active: string; keys: Record<string, string> } {
  const active = (process.env.AUTHCLAW_SESSION_KEY_VERSION || "v1").trim().toLowerCase() || "v1";
  const keys = Object.fromEntries(
    Object.entries(process.env)
      .filter(([name, value]) => name.startsWith("SESSION_SECRET_V") && Boolean(value))
      .map(([name, value]) => [name.slice("SESSION_SECRET_".length).toLowerCase(), value as string])
  );
  const secret = process.env.SESSION_SECRET || (process.env.NODE_ENV !== "production" ? "authclaw-local-session-secret" : "");
  if (!keys[active] && secret) keys[active] = secret;
  if (!keys[active]) throw new Error("SESSION_SECRET is required for OIDC state protection");
  return { active, keys };
}