import { createHash, createHmac, randomBytes } from "node:crypto";

export function oidcServiceHeaders(path: string, body: string): Record<string, string> {
  if (!["/v1/auth/oidc/start", "/v1/auth/oidc/callback"].includes(path)) {
    throw new Error("Invalid OIDC service scope");
  }
  const secret = process.env.OIDC_BFF_EXCHANGE_SECRET || "";
  if (secret.length < 32) throw new Error("OIDC service authentication unavailable");
  const context = `${Math.floor(Date.now() / 1000)};${randomBytes(16).toString("hex")}`;
  const digest = createHash("sha256").update(body).digest("hex");
  const material = `authclaw:oidc-service:v1\nPOST\n${path}\n${context}\n${digest}`;
  return {
    "Content-Type": "application/json",
    "x-authclaw-oidc-context": context,
    "x-authclaw-oidc-signature": createHmac("sha256", secret).update(material).digest("hex"),
  };
}
