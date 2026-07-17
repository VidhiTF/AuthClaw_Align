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
