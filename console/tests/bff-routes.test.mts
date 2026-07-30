import assert from "node:assert/strict";
import test from "node:test";
import { resolveBffRoute } from "../src/lib/bff-routes.ts";

test("maps approved BFF routes and rejects broader proxy access", () => {
  assert.deepEqual(resolveBffRoute("GET", "users"), { backendPath: "/v1/users", body: "none", status: undefined });
  assert.deepEqual(resolveBffRoute("POST", "red-team"), { backendPath: "/v1/red-team/runs", body: "json", status: 201 });
  assert.deepEqual(resolveBffRoute("POST", "users/me/mfa/disable"), { backendPath: "/v1/users/me/mfa/disable", body: "json", status: undefined });
  assert.deepEqual(resolveBffRoute("POST", "approvals/a-1/approve"), { backendPath: "/v1/workflows/approvals/a-1/approve", body: "optional-json", status: undefined });
  assert.deepEqual(resolveBffRoute("POST", "ephemeral-workers/tokens/t-1/revoke"), { backendPath: "/v1/ephemeral-workers/tokens/t-1/revoke", body: "none", status: undefined });
  assert.deepEqual(resolveBffRoute("GET", "findings/summary/dashboard"), { backendPath: "/v1/findings/summary/dashboard", body: "none", status: undefined });
  assert.deepEqual(resolveBffRoute("POST", "data-subject-requests/r-1/verify"), { backendPath: "/v1/data-subject-requests/r-1/verify", body: "json", status: undefined });
  assert.deepEqual(resolveBffRoute("DELETE", "api-keys/k-1"), { backendPath: "/v1/api-keys/k-1", body: "none", status: 204 });
  assert.equal(resolveBffRoute("DELETE", "users/me"), null);
  assert.equal(resolveBffRoute("POST", "auth/login"), null);
  assert.equal(resolveBffRoute("GET", "admin/secrets"), null);
});
