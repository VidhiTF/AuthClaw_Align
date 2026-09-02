import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const agentClient = fs.readFileSync(
  new URL("../src/lib/agent-client.ts", import.meta.url),
  "utf8",
);
const liteHealth = fs.readFileSync(
  new URL("../src/app/api/lite-health/route.ts", import.meta.url),
  "utf8",
);
const apiClient = fs.readFileSync(
  new URL("../src/lib/api-client.ts", import.meta.url),
  "utf8",
);
const onboardingVerify = fs.readFileSync(
  new URL("../src/app/api/onboarding/verify/route.ts", import.meta.url),
  "utf8",
);

test("Agent UI uses tenant-scoped internal RAG chat endpoints", () => {
  assert.match(agentClient, /backendFetch\("\/v1\/chat\/sessions"/);
  assert.match(agentClient, /\/v1\/chat\/sessions\/\$\{encodeURIComponent\(sessionId\)\}\/message/);
  assert.doesNotMatch(agentClient, /agentFetch\("\/chat/);
  assert.doesNotMatch(agentClient, /provider-credentials/);
});

test("Agent readiness uses the canonical ACL-11 health endpoint", () => {
  assert.match(liteHealth, /agentFetch\("\/api\/v1\/agent\/health\/ready"\)/);
  assert.doesNotMatch(liteHealth, /agentFetch\("\/chat/);
});

test("invitation sessions store only the backend opaque token", () => {
  assert.match(onboardingVerify, /data\.session_token/);
  assert.doesNotMatch(onboardingVerify, /sessionStore|data\.api_key/);
});

test("agent requests validate the canonical backend session before dispatch", () => {
  const validation = apiClient.indexOf('fetchBackend(`${BACKEND_URL}/v1/auth/me`');
  const dispatch = apiClient.indexOf("fetch(`${AGENT_URL}${path}`");

  assert.ok(validation >= 0 && validation < dispatch);
  assert.match(apiClient, /if \(!validation\.ok\)/);
  assert.match(apiClient, /return \{ payload: null, session: null \}/);
  assert.doesNotMatch(apiClient, /sessionStore|sessions\.json/);
});
