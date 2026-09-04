import { createHash, createHmac, randomBytes } from "node:crypto";
import { isIP } from "node:net";
import { validateBffClientIPConfig } from "./bff-client-ip-config.ts";

// Server-side only. The deployment must restrict console ingress to the ALB,
// whose append-mode XFF places the actual browser peer last, after caller input.
export function bffClientIPHeaders(request: Request, body: string): Record<string, string> {
  validateBffClientIPConfig();
  if (process.env.AUTHCLAW_BFF_CLIENT_IP_ENABLED !== "true") return {};
  const chain = request.headers.get("x-forwarded-for")?.split(",") ?? [];
  const ip = chain.at(-1)?.trim() ?? "";
  if (!ip || ip.includes("%") || isIP(ip) === 0) {
    throw new Error("ALB client identity unavailable");
  }
  const context = `${ip};${Math.floor(Date.now() / 1000)};${randomBytes(16).toString("hex")}`;
  const digest = createHash("sha256").update(body).digest("hex");
  const material = `authclaw:bff-client-ip:v1\nPOST\n/v1/auth/login\n${context}\n${digest}`;
  const signature = createHmac("sha256", process.env.BFF_CLIENT_IP_SECRET!)
    .update(material).digest("hex");
  return {
    "x-authclaw-client-context": context,
    "x-authclaw-client-signature": signature,
  };
}
