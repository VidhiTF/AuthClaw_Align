import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import test from "node:test";

process.env.SESSION_SECRET = "oidc-state-test-secret";
process.env.AUTHCLAW_OIDC_STATE_STORE_PATH = path.join(os.tmpdir(), `authclaw-oidc-state-${process.pid}.json`);
const { consumeOidcState, openOidcState, registerOidcState, sealOidcState } = await import("../src/lib/oidc-state.ts");

const validState = () => ({
  state: "state-token",
  nonce: "nonce-token",
  tenantName: "Acme",
  redirectUri: "https://app.example.com/api/auth/oidc/callback",
  issuedAt: Date.now(),
});

test("OIDC state round trips when authentic", () => {
  const state = validState();
  assert.deepEqual(openOidcState(sealOidcState(state)), state);
});

test("OIDC state rejects tampering", () => {
  const sealed = sealOidcState(validState());
  const tampered = `${sealed[0] === "a" ? "b" : "a"}${sealed.slice(1)}`;
  assert.throws(() => openOidcState(tampered), /Invalid OIDC state/);
});

test("OIDC state rejects expiry", () => {
  const expired = { ...validState(), issuedAt: Date.now() - 600_001 };
  assert.throws(() => openOidcState(sealOidcState(expired)), /Invalid OIDC state/);
});

test("OIDC state is single use", () => {
  const sealed = sealOidcState(validState());
  registerOidcState(sealed);
  consumeOidcState(sealed);
  assert.throws(() => consumeOidcState(sealed), /Invalid OIDC state/);
});

test("OIDC state remains valid across a session-key rotation", () => {
  process.env.AUTHCLAW_SESSION_KEY_VERSION = "v1";
  process.env.SESSION_SECRET_V1 = "oidc-state-test-secret";
  const state = validState();
  const sealed = sealOidcState(state);
  registerOidcState(sealed);

  process.env.AUTHCLAW_SESSION_KEY_VERSION = "v2";
  process.env.SESSION_SECRET_V2 = "new-oidc-state-test-secret";
  assert.deepEqual(openOidcState(sealed), state);
  consumeOidcState(sealed);
});
