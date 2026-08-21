import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

for (const route of ["api/auth/login/route.ts", "api/onboarding/verify/route.ts"]) {
  test(`${route} logs internal errors and returns a generic response`, () => {
    const source = fs.readFileSync(path.join(root, "src/app", route), "utf8");
    assert.match(source, /console\.error\([^;]+, error\)/);
    assert.match(source, /(?:message|detail): "Authentication failed"/);
    assert.doesNotMatch(source, /(?:message|detail):[^\n]*(?:error\.message|\$\{)/);
  });
}

test("BFF 5xx responses do not expose upstream exception details", () => {
  const source = fs.readFileSync(path.join(root, "src/lib/api-client.ts"), "utf8");
  assert.match(source, /status >= 500 \? "Request failed" : message/);
  assert.match(source, /if \(response\.status < 500\) errorDetail = apiErrorMessage/);
});
