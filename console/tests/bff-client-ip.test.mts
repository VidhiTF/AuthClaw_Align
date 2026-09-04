import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import test from "node:test";
import type { TestContext } from "node:test";
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
