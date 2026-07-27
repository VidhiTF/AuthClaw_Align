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

test("invitation sessions use backend-authoritative scopes", () => {
  assert.match(onboardingVerify, /scopes: data\.scopes/g);
  assert.doesNotMatch(onboardingVerify, /scopes: \["admin", "read", "write"\]/);
});

test("agent requests reject revoked canonical sessions before dispatch", () => {
  const validation = apiClient.indexOf('fetchBackend(`${BACKEND_URL}/v1/auth/me`');
  const dispatch = apiClient.indexOf("fetch(`${AGENT_URL}${path}`");

  assert.ok(validation >= 0 && validation < dispatch);
  assert.match(apiClient, /validation\.status === 401 \|\| validation\.status === 403/);
  assert.match(apiClient, /sessionStore\.deleteSession\(context\.session\.sessionId\)/);
});
