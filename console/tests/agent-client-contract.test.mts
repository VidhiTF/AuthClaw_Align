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

test("v3 signer binds a fresh backend MFA assertion to the actor action and body", () => {
  const previous = process.env.AUTHCLAW_INTERNAL_SERVICE_SECRET;
  const path = "/approve/approval-17";
  const body = JSON.stringify({ comment: "approved" });
  const bodyHash = createHash("sha256").update(body).digest("hex");
  process.env.AUTHCLAW_INTERNAL_SERVICE_SECRET = JSON.stringify({
    active_key_id: "v1",
    keys: { v1: {
      secret: "test-only-secret".repeat(3), service: "console", audience: "agent",
      endpoints: ["POST /approve/*"],
    } },
  });
  try {
    const signed = controlPlaneHeaders(
      new URL(`https://agent.invalid${path}`), "POST", body, "application/json",
      { tenantId: "tenant", userId: "backend-user-uuid", role: "owner" },
      { verified_at: Math.floor(Date.now() / 1000), operation: `POST ${path}`,
        body_sha256: bodyHash, assertion_id: "a".repeat(32) },
    );
    assert.equal(signed["X-AuthClaw-Version"], "3");
    assert.equal(signed["X-AuthClaw-MFA-Operation"], `POST ${path}`);
    assert.equal(signed["X-AuthClaw-MFA-Body-SHA256"], bodyHash);
    assert.equal(signed["X-AuthClaw-MFA-Assertion-ID"], "a".repeat(32));
    assert.throws(() => controlPlaneHeaders(
      new URL(`https://agent.invalid${path}`), "POST", body, "application/json",
      { tenantId: "tenant", userId: "backend-user-uuid", role: "owner" },
    ));
    assert.throws(() => controlPlaneHeaders(
      new URL(`https://agent.invalid${path}`), "POST", body, "application/json",
      { tenantId: "tenant", userId: "backend-user-uuid", role: "owner" },
      { verified_at: Math.floor(Date.now() / 1000), operation: "POST /approve/other",
        body_sha256: bodyHash, assertion_id: "b".repeat(32) },
    ));
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

test("privileged agent requests verify MFA in backend and never forward the code", async () => {
  const calls: Array<{ url: string; body: string; headers: Headers }> = [];
  const path = "/approve/approval-17";
  const secret = "test-only-secret".repeat(3);
  const modules: Record<string, unknown> = {
    "node:crypto": { createHash, createHmac, randomBytes },
    "next/server": { NextResponse: { json: (body: unknown, init?: { status?: number }) => ({ body, status: init?.status ?? 200 }) } },
    "next/headers": { cookies: async () => ({ get: () => ({ value: "acl_session_valid" }) }) },
    "@/lib/cookie-options": { sessionCookieName: () => "authclaw_session" },
  };
  const load = (source: string) => {
    const exports: Record<string, unknown> = {};
    vm.runInNewContext(ts.transpileModule(source, { compilerOptions: {
      module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022,
    } }).outputText, {
      exports, require: (name: string) => modules[name], Error, Headers, AbortSignal,
      URL, URLSearchParams, Response, Buffer, JSON,
      process: { env: {
        API_URL: "http://backend.private:8000", AGENT_INTERNAL_URL: "http://agent.private:8001",
        AUTHCLAW_INTERNAL_SERVICE_SECRET: JSON.stringify({ active_key_id: "v1", keys: {
          v1: { secret, service: "console", audience: "agent", endpoints: ["POST /approve/*"] },
        } }),
      } },
      fetch: async (url: string, options: RequestInit = {}) => {
        const body = typeof options.body === "string" ? options.body : "";
        const headers = new Headers(options.headers);
        calls.push({ url, body, headers });
        if (url.endsWith("/v1/auth/me")) return Response.json({
          id: "backend-user-uuid", tenant_id: "backend-tenant-uuid", role: "owner", scopes: [],
        });
        if (url.endsWith("/v1/auth/mfa/agent-assertion")) {
          const request = JSON.parse(body);
          assert.equal(request.code, "654321");
          return Response.json({
            verified_at: Math.floor(Date.now() / 1000), operation: `POST ${path}`,
            body_sha256: request.body_sha256, assertion_id: "f".repeat(32), role: "admin",
          });
        }
        return Response.json({ status: "approved" });
      },
    });
    return exports;
  };
  modules["./control-plane-auth"] = load(fs.readFileSync(
    new URL("../src/lib/control-plane-auth.ts", import.meta.url), "utf8",
  ));
  modules["./errors"] = load(fs.readFileSync(new URL("../src/lib/errors.ts", import.meta.url), "utf8"));
  const api = load(apiClient) as { agentFetch: (path: string, options: RequestInit) => Promise<unknown> };

  await api.agentFetch(path, { method: "POST", body: JSON.stringify({ mfa_code: "654321", comment: "ok" }) });

  const forwarded = calls.at(-1)!;
  assert.equal(forwarded.url, `http://agent.private:8001${path}`);
  assert.deepEqual(JSON.parse(forwarded.body), { comment: "ok" });
  assert.doesNotMatch(forwarded.body, /654321|mfa_code/);
  assert.equal(forwarded.headers.get("x-authclaw-version"), "3");
  assert.equal(forwarded.headers.get("x-authclaw-user-id"), "backend-user-uuid");
  assert.equal(forwarded.headers.get("x-authclaw-role"), "admin");
  assert.equal(forwarded.headers.get("x-authclaw-mfa-operation"), `POST ${path}`);
});

test("production BFF route dispatches both privileged agent stages", async () => {
  const calls: Array<{ path: string; body: string }> = [];
  const routeSource = fs.readFileSync(
    new URL("../src/app/api/agent/approvals/[id]/[action]/route.ts", import.meta.url),
    "utf8",
  );
  const exports: Record<string, unknown> = {};
  const json = (body: unknown, init?: { status?: number }) => ({ body, status: init?.status ?? 200 });
  vm.runInNewContext(ts.transpileModule(routeSource, { compilerOptions: {
    module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022,
  } }).outputText, {
    exports,
    require: (name: string) => {
      if (name === "next/server") return { NextResponse: { json } };
      if (name === "@/lib/api-client") return {
        agentFetch: async (path: string, options: RequestInit) => {
          calls.push({ path, body: String(options.body) });
          return { status: path.slice(1, path.indexOf("/", 1)) + "d" };
        },
        handleApiError: (error: unknown) => json({ error: String(error) }, { status: 500 }),
        routeParam: async (context: { params: Promise<Record<string, string>> }, key: string) =>
          (await context.params)[key],
      };
      throw new Error(`unexpected module: ${name}`);
    },
    Request, Response, JSON, Error,
  });

  const post = exports.POST as (
    request: Request,
    context: { params: Promise<{ id: string; action: string }> },
  ) => Promise<{ status: number; body: unknown }>;
  for (const action of ["approve", "execute"]) {
    const response = await post(
      new Request("http://console/api/agent/approvals/approval-17/" + action, {
        method: "POST",
        body: JSON.stringify({ mfa_code: "654321", comment: "ok" }),
        headers: { "content-type": "application/json" },
      }),
      { params: Promise.resolve({ id: "approval-17", action }) },
    );
    assert.equal(response.status, 200);
  }
  assert.deepEqual(calls.map(({ path }) => path), [
    "/approve/approval-17",
    "/execute/approval-17",
  ]);
  assert.ok(calls.every(({ body }) => JSON.parse(body).mfa_code === "654321"));
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
