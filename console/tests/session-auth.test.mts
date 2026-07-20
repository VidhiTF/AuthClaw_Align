import assert from "node:assert/strict";
import test from "node:test";

const { authenticateSessionCookie } = await import("../src/lib/session-auth.ts");

const session = {
  sessionId: "valid-session",
  userId: "user-1",
  tenantId: "tenant-1",
  scopes: ["read"],
  role: "viewer",
  apiKey: "secret",
  createdAt: Date.now(),
};
const store = { getSession: (id: string) => id === session.sessionId ? session : undefined };
const cookie = (changes = {}) => JSON.stringify({
  sessionId: session.sessionId,
  userId: session.userId,
  tenantId: session.tenantId,
  scopes: session.scopes,
  role: session.role,
  email: "user@example.com",
  ...changes,
});

test("rejects a forged session cookie", () => {
  assert.equal(authenticateSessionCookie(cookie({ sessionId: "forged" }), store), undefined);
});

test("rejects a modified role", () => {
  assert.equal(authenticateSessionCookie(cookie({ role: "owner" }), store), undefined);
});

test("rejects a modified tenant", () => {
  assert.equal(authenticateSessionCookie(cookie({ tenantId: "tenant-2" }), store), undefined);
});

test("rejects a modified expiry", () => {
  assert.equal(authenticateSessionCookie(cookie({ expiresAt: Date.now() + 86400000 }), store), undefined);
});
