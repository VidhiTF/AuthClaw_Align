import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { resolveBffRoute } from "../src/lib/bff-routes.ts";

test("developer layout requires an active tenantless platform profile", () => {
  const source = readFileSync(new URL("../src/app/developer/layout.tsx", import.meta.url), "utf8");
  assert.ok(source.includes("principal.tenant_id === null"));
  assert.ok(source.includes('principal.role === "platform_admin"'));
  assert.ok(source.includes("principal.is_active === true"));
  assert.ok(source.includes('scopes.includes("platform.admin")'));
});

test("maps approved BFF routes and rejects broader proxy access", () => {
  assert.deepEqual(resolveBffRoute("GET", "users"), { backendPath: "/v1/users", body: "none", status: undefined });
  assert.deepEqual(resolveBffRoute("POST", "red-team"), { backendPath: "/v1/red-team/runs", body: "json", status: 201 });
  assert.deepEqual(resolveBffRoute("POST", "tenants"), { backendPath: "/v1/tenants", body: "json", status: 201 });
  assert.deepEqual(resolveBffRoute("POST", "users/me/mfa/disable"), { backendPath: "/v1/users/me/mfa/disable", body: "json", status: undefined });
  assert.deepEqual(resolveBffRoute("POST", "approvals/a-1/approve"), { backendPath: "/v1/workflows/approvals/a-1/approve", body: "optional-json", status: undefined });
  assert.deepEqual(resolveBffRoute("POST", "ephemeral-workers/tokens/t-1/revoke"), { backendPath: "/v1/ephemeral-workers/tokens/t-1/revoke", body: "none", status: undefined });
  assert.deepEqual(resolveBffRoute("GET", "findings/summary/dashboard"), { backendPath: "/v1/findings/summary/dashboard", body: "none", status: undefined });
  assert.deepEqual(resolveBffRoute("POST", "data-subject-requests/r-1/verify"), { backendPath: "/v1/data-subject-requests/r-1/verify", body: "json", status: undefined });
  assert.deepEqual(resolveBffRoute("GET", "access-requests"), { backendPath: "/api/public/v1/access-requests", body: "none", status: undefined });
  assert.deepEqual(resolveBffRoute("PATCH", "access-requests/AR-123/status"), { backendPath: "/api/public/v1/access-requests/AR-123/status", body: "json", status: undefined });
  assert.deepEqual(resolveBffRoute("DELETE", "api-keys/k-1"), { backendPath: "/v1/api-keys/k-1", body: "none", status: 204 });
  assert.equal(resolveBffRoute("DELETE", "access-requests/AR-123"), null);
  assert.equal(resolveBffRoute("DELETE", "users/me"), null);
  assert.equal(resolveBffRoute("POST", "auth/login"), null);
  assert.equal(resolveBffRoute("GET", "admin/secrets"), null);
});

test("notification mutations surface failures instead of reporting stale success", () => {
  const components = [
    "../src/components/notification-bell.tsx",
    "../src/app/(console)/notifications/page.tsx",
  ];

  for (const component of components) {
    const source = readFileSync(new URL(component, import.meta.url), "utf8");
    assert.ok(source.includes("if (!response.ok) throw new Error"), component);
    assert.ok(source.includes('role="alert"'), component);
    assert.ok(source.includes("await load()"), component);
    assert.ok(!source.includes(".catch(() => undefined)"), component);
  }
});
