import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import vm from "node:vm";
import { createHash, createHmac, randomBytes } from "node:crypto";
import ts from "typescript";
import { canonicalQuery, controlPlaneHeaders } from "../src/lib/control-plane-auth.ts";

test("v2 signer binds query and uses explicit active service/endpoint keys", () => {
  assert.equal(canonicalQuery("b=2&a=x+y&a=%C3%A9"), "a=x%20y&a=%C3%A9&b=2");
  for (const query of ["x=%FF", "x=%", "x=1&&y=2"]) assert.throws(() => canonicalQuery(query));
  const previous = process.env.AUTHCLAW_INTERNAL_SERVICE_SECRET;
  const principal = { tenantId: "tenant", userId: "actor", role: "owner" };
  const key = { secret: "test-only-secret".repeat(3), service: "console", audience: "agent", endpoints: ["POST /chat"] };
  const ring = { active_key_id: "old", keys: { old: key, next: { ...key, secret: "different-test-secret".repeat(3) } } };
  try {
    for (const active of ["old", "next", "old"]) {
      ring.active_key_id = active;
      process.env.AUTHCLAW_INTERNAL_SERVICE_SECRET = JSON.stringify(ring);
      const signed = controlPlaneHeaders(new URL("https://agent.invalid/chat?x=1"), "POST", "{}", "application/json", principal);
      assert.equal(signed["X-AuthClaw-Key-ID"], active);
      assert.equal(signed["X-AuthClaw-Version"], "2");
      assert.match(signed["X-AuthClaw-Nonce"], /^[a-f0-9]{32}$/);
    }
    for (const [method, path] of [["GET", "/chat"], ["POST", "/elsewhere"], ["POST", "/chat#fragment"]]) {
      assert.throws(() => controlPlaneHeaders(new URL(`https://agent.invalid${path}`), method, "", "", principal));
    }
    process.env.AUTHCLAW_INTERNAL_SERVICE_SECRET = "legacy-raw-secret";
    assert.throws(() => controlPlaneHeaders(new URL("https://agent.invalid/chat"), "POST", "", "", principal));
  } finally {
    if (previous === undefined) delete process.env.AUTHCLAW_INTERNAL_SERVICE_SECRET;
    else process.env.AUTHCLAW_INTERNAL_SERVICE_SECRET = previous;
  }
});

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
  const dispatch = apiClient.indexOf("fetch(url.toString()");

  assert.ok(validation >= 0 && validation < dispatch);
  assert.match(apiClient, /if \(!validation\.ok\)/);
  assert.match(apiClient, /return \{ payload: null, session: null \}/);
  assert.doesNotMatch(apiClient, /sessionStore|sessions\.json/);
});

test("readiness authenticates before probes, sanitizes diagnostics, and distinguishes outages", async () => {
  const errors = fs.readFileSync(new URL("../src/lib/errors.ts", import.meta.url), "utf8");
  for (const [token, identityStatus, expected, healthy] of [["", 200, 401, false], ["malformed", 200, 401, false], ["acl_session_expired", 401, 401, false], ["acl_session_revoked", 401, 401, false], ["acl_session_valid", 503, 503, false], ["acl_session_valid", 200, 200, false], ["acl_session_valid", 200, 200, true]] as const) {
    const requests: string[] = [];
    const json = (body: unknown, init?: { status?: number }) => ({ body, status: init?.status ?? 200, cookies: { delete() {} } });
    const modules: Record<string, unknown> = { "node:crypto": { createHash, createHmac, randomBytes }, "next/server": { NextResponse: { json } }, "next/headers": { cookies: async () => ({ get: () => token ? { value: token } : undefined }) }, "@/lib/cookie-options": { sessionCookieName: () => "authclaw_session" } };
    const load = (source: string) => {
      const exports: Record<string, unknown> = {};
      vm.runInNewContext(ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText, {
        exports, require: (name: string) => { assert.ok(name in modules, name); return modules[name]; }, Error, Headers, AbortSignal, URL, URLSearchParams, Response, Buffer,
        process: { env: { API_URL: "http://backend.private:8000", GATEWAY_INTERNAL_URL: "http://gateway.private:8080", AUTHCLAW_INTERNAL_SERVICE_SECRET: JSON.stringify({ active_key_id: "test", keys: { test: { secret: "test-only-secret".repeat(3), service: "console", audience: "agent", endpoints: ["GET /api/v1/agent/health/ready"] } } }) } },
        fetch: async (url: string) => {
          requests.push(url);
          if (url.endsWith("/v1/auth/me")) return Response.json({ id: "user", tenant_id: "tenant", role: "owner", scopes: [] }, { status: identityStatus });
          const body = url.endsWith("/health") ? { secret_management: { configured: true } } : url.endsWith("/ready") ? { status: "ready" } : url.endsWith("/active") ? { id: "policy" } : [{ status: "active" }];
          return Response.json(healthy ? body : { detail: "http://private-service/secret" }, { status: healthy ? 200 : 503 });
        },
      });
      return exports;
    };
    modules["./control-plane-auth"] = load(fs.readFileSync(new URL("../src/lib/control-plane-auth.ts", import.meta.url), "utf8"));
    modules["./errors"] = load(errors);
    modules["@/lib/api-client"] = load(apiClient);
    const response = await (load(liteHealth).GET as () => Promise<{ status: number; body: unknown }>)();
    assert.equal(response.status, expected);
    assert.doesNotMatch(JSON.stringify(response.body), /private|secret\/|http:\/\//);
    assert.equal(requests.some((url) => !url.endsWith("/v1/auth/me")), expected === 200);
    if (!token || token === "malformed") assert.equal(requests.length, 0);
    if (expected === 200) assert.ok(requests.includes("http://gateway.private:8080/health"));
    if (expected === 200) assert.equal((response.body as { ready: boolean }).ready, healthy);
  }
});
