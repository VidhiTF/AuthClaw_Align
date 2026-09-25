import { createHash, createHmac, randomBytes } from "node:crypto";

export function bodySha256(body: string): string {
  return createHash("sha256").update(body).digest("hex");
}

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

function endpointAllowed(endpoints: string[], method: string, path: string, privileged: boolean): boolean {
  if (endpoints.includes(`${method} ${path}`)) return true;
  if (!privileged || method !== "POST") return false;
  return (endpoints.includes("POST /approve/*") && /^\/approve\/[A-Za-z0-9._:-]+$/.test(path))
    || (endpoints.includes("POST /execute/*") && /^\/execute\/[A-Za-z0-9._:-]+$/.test(path));
}

export function controlPlaneHeaders(
  url: URL, method: string, body: string, contentType: string,
  principal: { tenantId: string; userId: string; role: string },
  mfa?: { verified_at: number; operation: string; body_sha256: string; assertion_id: string },
): Record<string, string> {
  const ring = JSON.parse(process.env.AUTHCLAW_INTERNAL_SERVICE_SECRET || "{}");
  const id = ring.active_key_id;
  const key = ring.keys?.[id];
  if (typeof id !== "string" || !key || typeof key.secret !== "string" || Buffer.byteLength(key.secret) < 32
      || key.service !== "console" || key.audience !== "agent" || !Array.isArray(key.endpoints)
      || !endpointAllowed(key.endpoints, method, url.pathname, Boolean(mfa))
      || url.hash || Buffer.byteLength(body) > 1024 * 1024) {
    throw new Error("Service signing configuration or request is invalid");
  }
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce = randomBytes(16).toString("hex");
  const version = mfa ? "3" : "2";
  const bodyHash = bodySha256(body);
  if (mfa && (mfa.operation !== `${method} ${url.pathname}` || mfa.body_sha256 !== bodyHash
      || !Number.isInteger(mfa.verified_at) || !/^[a-f0-9]{32}$/.test(mfa.assertion_id))) {
    throw new Error("Invalid MFA assertion binding");
  }
  const fields = [`authclaw:service-request:v${version}`, timestamp, nonce, key.service, key.audience, id,
    method, url.pathname, canonicalQuery(url.search.slice(1)), bodyHash,
    contentType, principal.tenantId, principal.userId, principal.role];
  if (mfa) fields.push(
    mfa.verified_at.toString(), mfa.operation, mfa.body_sha256, mfa.assertion_id,
  );
  if (fields.some((value) => typeof value !== "string" || /[\x00-\x1f\x7f]/.test(value))) {
    throw new Error("Invalid signed field");
  }
  return {
    "X-AuthClaw-Version": version, "X-AuthClaw-Timestamp": timestamp, "X-AuthClaw-Nonce": nonce,
    "X-AuthClaw-Service": key.service, "X-AuthClaw-Audience": key.audience, "X-AuthClaw-Key-ID": id,
    "X-AuthClaw-Tenant-ID": principal.tenantId, "X-AuthClaw-User-ID": principal.userId,
    "X-AuthClaw-Role": principal.role,
    ...(mfa ? {
      "X-AuthClaw-MFA-Verified-At": mfa.verified_at.toString(),
      "X-AuthClaw-MFA-Operation": mfa.operation,
      "X-AuthClaw-MFA-Body-SHA256": mfa.body_sha256,
      "X-AuthClaw-MFA-Assertion-ID": mfa.assertion_id,
    } : {}),
    "X-AuthClaw-Signature": createHmac("sha256", key.secret).update(fields.join("\n")).digest("hex"),
  };
}
