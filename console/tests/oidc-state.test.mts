import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";

process.env.SESSION_SECRET = "oidc-state-test-secret";
const { openOidcState, sealOidcState } = await import("../src/lib/oidc-state.ts");
const { oidcServiceHeaders } = await import("../src/lib/oidc-service.ts");

const validState = () => randomBytes(32).toString("base64url");

test("OIDC state round trips when authentic", () => {
  const state = validState();
  assert.deepEqual(openOidcState(sealOidcState(state)), state);
});

test("OIDC state rejects tampering", () => {
  const sealed = sealOidcState(validState());
  const tampered = `${sealed[0] === "a" ? "b" : "a"}${sealed.slice(1)}`;
  assert.throws(() => openOidcState(tampered), /Invalid OIDC state/);
});

test("OIDC state rejects legacy cookies after the approved drain", () => {
  assert.throws(() => openOidcState("legacy.payload.signature"), /Invalid OIDC state/);
});

test("OIDC cookie contains only opaque identity and authenticating metadata", () => {
  const sealed = sealOidcState(validState());
  assert.equal(sealed.split(".").length, 4);
  assert.doesNotMatch(sealed, /tenant|nonce|redirect|issuer/);
});

test("OIDC state remains valid across a session-key rotation", () => {
  process.env.AUTHCLAW_SESSION_KEY_VERSION = "v1";
  process.env.SESSION_SECRET_V1 = "oidc-state-test-secret";
  const state = validState();
  const sealed = sealOidcState(state);

  process.env.AUTHCLAW_SESSION_KEY_VERSION = "v2";
  process.env.SESSION_SECRET_V2 = "new-oidc-state-test-secret";
  assert.deepEqual(openOidcState(sealed), state);
});

test("OIDC service credentials are endpoint scoped and bind the outgoing body", () => {
  process.env.OIDC_BFF_EXCHANGE_SECRET = "test-oidc-service-key-with-32-characters";
  const headers = oidcServiceHeaders("/v1/auth/oidc/callback", "{}");
  assert.match(headers["x-authclaw-oidc-signature"], /^[0-9a-f]{64}$/);
  assert.throws(() => oidcServiceHeaders("/v1/users", "{}"));
  delete process.env.OIDC_BFF_EXCHANGE_SECRET;
  assert.throws(() => oidcServiceHeaders("/v1/auth/oidc/callback", "{}"));
});
