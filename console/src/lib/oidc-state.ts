import { createHmac, timingSafeEqual } from "node:crypto";
import { sessionKeyRing } from "./session-keys.ts";

// Only the opaque ID enters the browser. Context/expiry live in Redis, reached
// through authenticated backend operations, never a console replica file.
export function sealOidcState(identifier: string) {
  if (!/^[A-Za-z0-9_-]{43}$/.test(identifier)) throw new Error("Invalid OIDC state");
  const { active, keys } = sessionKeyRing();
  const payload = `v2.${identifier}.${active}`;
  const signature = createHmac("sha256", keys[active]).update(payload).digest("base64url");
  return `${payload}.${signature}`;
}

export function openOidcState(value: string): string {
  const parts = value.split(".");
  if (parts.length !== 4 || parts[0] !== "v2" || !/^[A-Za-z0-9_-]{43}$/.test(parts[1])) {
    throw new Error("Invalid OIDC state");
  }
  const key = sessionKeyRing().keys[parts[2]];
  if (!key) throw new Error("Invalid OIDC state");
  const expected = createHmac("sha256", key).update(parts.slice(0, 3).join(".")).digest();
  const actual = Buffer.from(parts[3], "base64url");
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
    throw new Error("Invalid OIDC state");
  }
  return parts[1];
}
