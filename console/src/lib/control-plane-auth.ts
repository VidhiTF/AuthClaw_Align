import { createHash, createHmac, randomBytes } from "node:crypto";

export function canonicalQuery(query: string): string {
  if (!query) return "";
  const encode = (value: string) => encodeURIComponent(decodeURIComponent(value.replace(/\+/g, " ")))
    .replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
  return query.split("&").map((part) => {
    if (!part) throw new Error("Empty query pair");
    const index = part.indexOf("=");
    return index < 0 ? [encode(part), ""] : [encode(part.slice(0, index)), encode(part.slice(index + 1))];
  }).sort((a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)
    .map(([name, value]) => `${name}=${value}`).join("&");
}

export function controlPlaneHeaders(
  url: URL, method: string, body: string, contentType: string,
  principal: { tenantId: string; userId: string; role: string },
): Record<string, string> {
  const ring = JSON.parse(process.env.AUTHCLAW_INTERNAL_SERVICE_SECRET || "{}");
  const id = ring.active_key_id;
  const key = ring.keys?.[id];
  if (typeof id !== "string" || !key || typeof key.secret !== "string" || Buffer.byteLength(key.secret) < 32
      || key.service !== "console" || key.audience !== "agent" || !Array.isArray(key.endpoints)
      || !key.endpoints.includes(`${method} ${url.pathname}`) || url.hash || Buffer.byteLength(body) > 1024 * 1024) {
    throw new Error("Service signing configuration or request is invalid");
  }
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce = randomBytes(16).toString("hex");
  const fields = ["authclaw:service-request:v2", timestamp, nonce, key.service, key.audience, id,
    method, url.pathname, canonicalQuery(url.search.slice(1)), createHash("sha256").update(body).digest("hex"),
    contentType, principal.tenantId, principal.userId, principal.role];
  if (fields.some((value) => typeof value !== "string" || /[\x00-\x1f\x7f]/.test(value))) {
    throw new Error("Invalid signed field");
  }
  return {
    "X-AuthClaw-Version": "2", "X-AuthClaw-Timestamp": timestamp, "X-AuthClaw-Nonce": nonce,
    "X-AuthClaw-Service": key.service, "X-AuthClaw-Audience": key.audience, "X-AuthClaw-Key-ID": id,
    "X-AuthClaw-Tenant-ID": principal.tenantId, "X-AuthClaw-User-ID": principal.userId,
    "X-AuthClaw-Role": principal.role,
    "X-AuthClaw-Signature": createHmac("sha256", key.secret).update(fields.join("\n")).digest("hex"),
  };
}
