import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import fs from "node:fs";
import test from "node:test";
import type { TestContext } from "node:test";
import ts from "typescript";
import { bffClientIPHeaders } from "../src/lib/bff-client-ip.ts";

function configure(t: TestContext) {
  const values = {
    AUTHCLAW_BFF_CLIENT_IP_ENABLED: "true",
    AUTHCLAW_CONSOLE_ALB_INGRESS_ONLY: "true",
    BFF_CLIENT_IP_SECRET: "test-signing-key-which-is-at-least-32-characters",
  };
  const previous = Object.fromEntries(Object.keys(values).map(key => [key, process.env[key]]));
  Object.assign(process.env, values);
  t.after(() => {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });
}

test("BFF signs the ALB-appended address and exact outgoing body", (t) => {
  configure(t);
  const body = '{"email":"test@example.com","password":"synthetic"}';
  const request = new Request("https://console.example/api/auth/login", {
    headers: { "x-forwarded-for": "192.0.2.66, 198.51.100.9" },
  });
  const headers = bffClientIPHeaders(request, body);
  const context = headers["x-authclaw-client-context"];
  assert.equal(context.split(";")[0], "198.51.100.9");
  const material = `authclaw:bff-client-ip:v1\nPOST\n/v1/auth/login\n${context}\n${createHash("sha256").update(body).digest("hex")}`;
  assert.equal(headers["x-authclaw-client-signature"],
    createHmac("sha256", process.env.BFF_CLIENT_IP_SECRET!).update(material).digest("hex"));
  assert.notEqual(bffClientIPHeaders(request, body)["x-authclaw-client-context"], context);
});

test("BFF refuses to sign without ingress guarantees or with invalid ALB address", (t) => {
  configure(t);
  process.env.AUTHCLAW_CONSOLE_ALB_INGRESS_ONLY = "false";
  assert.throws(() => bffClientIPHeaders(new Request("http://localhost"), "{}"));
  process.env.AUTHCLAW_CONSOLE_ALB_INGRESS_ONLY = "true";
  for (const value of ["", "198.51.100.9:123", "fe80::1%eth0"]) {
    assert.throws(() => bffClientIPHeaders(new Request("http://localhost", {
      headers: { "x-forwarded-for": value },
    }), "{}"));
  }
});

test("public auth signatures bind the target backend path", (t) => {
  configure(t);
  const path = "/v1/auth/password-reset/request", body = "{}";
  const headers = bffClientIPHeaders(new Request("https://console.example", { headers: { "x-forwarded-for": "198.51.100.9" } }), body, path);
  const material = `authclaw:bff-client-ip:v1\nPOST\n${path}\n${headers["x-authclaw-client-context"]}\n${createHash("sha256").update(body).digest("hex")}`;
  assert.equal(headers["x-authclaw-client-signature"], createHmac("sha256", process.env.BFF_CLIENT_IP_SECRET!).update(material).digest("hex"));
});

function publicRoutes(fetcher: typeof fetch) {
  function load(file: string, dependencies: Record<string, unknown>) {
    const source = fs.readFileSync(new URL(`../src/${file}`, import.meta.url), "utf8");
    const { outputText } = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS } });
    const exports: Record<string, unknown> = {};
    new Function("exports", "require", "fetch", outputText)(exports, (name: string) => {
      assert.ok(name in dependencies, `Unexpected dependency: ${name}`);
      return dependencies[name];
    }, fetcher);
    return exports;
  }
  const client = load("lib/api-client.ts", {
    crypto: { createHmac }, "next/headers": {}, "@/lib/cookie-options": {}, "./errors": {},
    "next/server": { NextResponse: { json: Response.json } }, "./bff-client-ip": { bffClientIPHeaders },
  });
  return (action: string) => load(`app/api/trust-center/public/[token]/${action}/route.ts`, {
    "@/lib/api-client": client,
  }).POST as (request: Request, context: { params: Promise<{ token: string }> }) => Promise<Response>;
}

test("auditor routes sign each browser IP and the exact outgoing path and body", async (t) => {
  configure(t);
  const sent: { url: string; options: RequestInit }[] = [];
  const route = publicRoutes(async (url, options) => {
    sent.push({ url: String(url), options: options! });
    return Response.json({ ok: true }, { status: 202 });
  });
  for (const ip of ["198.51.100.9", "2001:db8::2"]) {
    for (const [action, body] of [["request-access", undefined], ["request-access", '{"ignored":true}'], ["verify-access", '{ "otp": "123456" }']] as const) {
      const response = await route(action)(new Request("https://console.example", {
        method: "POST", body, headers: { "x-forwarded-for": `192.0.2.66, ${ip}` },
      }), { params: Promise.resolve({ token: "share+token" }) });
      assert.equal(response.status, 202);
      const { url, options } = sent.at(-1)!;
      assert.equal(url.endsWith(`/share%2Btoken/${action}`), true);
      assert.equal(options.method, "POST");
      assert.equal(options.body ?? "", action === "request-access" ? "" : '{"otp":"123456"}');
      const headers = new Headers(options.headers), context = headers.get("x-authclaw-client-context");
      assert.ok(context, "auditor request must carry signed browser identity");
      assert.equal(context.split(";")[0], ip);
      const material = `authclaw:bff-client-ip:v1\nPOST\n${new URL(url).pathname}\n${context}\n${createHash("sha256").update(String(options.body ?? "")).digest("hex")}`;
      assert.equal(headers.get("x-authclaw-client-signature"), createHmac("sha256", process.env.BFF_CLIENT_IP_SECRET!).update(material).digest("hex"));
    }
  }
});

test("auditor code requests fail closed on signing failure and preserve unsigned local mode", async (t) => {
  configure(t);
  let calls = 0;
  const post = publicRoutes(async () => { calls++; return new Response("unavailable", { status: 503 }); })("request-access");
  const request = () => new Request("https://console.example", { method: "POST" });
  const context = { params: Promise.resolve({ token: "share" }) };
  assert.equal((await post(request(), context)).status, 500);
  assert.equal(calls, 0);
  process.env.AUTHCLAW_BFF_CLIENT_IP_ENABLED = "false";
  const response = await post(request(), context);
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), {});
  assert.equal(calls, 1);
});
