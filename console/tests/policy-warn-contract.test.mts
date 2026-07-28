import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const policiesPage = fs.readFileSync(
  new URL("../src/app/(console)/policies/page.tsx", import.meta.url),
  "utf8",
);

test("ACL-17 policy builder preserves and exposes the warn action", () => {
  assert.match(policiesPage, /type RuleAction = [^;]*"warn"/);
  assert.match(policiesPage, /value === "warn"/);
  assert.match(
    policiesPage,
    /<option value="warn">Warn, redact, and pass<\/option>/,
  );
  assert.match(policiesPage, /`    action: \$\{rule\.action\}`/);
});
