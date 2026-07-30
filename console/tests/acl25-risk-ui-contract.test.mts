import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";


const root = path.resolve(import.meta.dirname, "..");
const riskPage = fs.readFileSync(
  path.join(root, "src", "app", "(console)", "risk", "page.tsx"),
  "utf8",
);


test("ACL-25 Risk UI exposes case category and severity rank", () => {
  assert.match(riskPage, /probe\.category/);
  assert.match(riskPage, /probe\.severity/);
  assert.match(riskPage, /severity_rank/);
  assert.match(riskPage, /RANK/);
});


test("ACL-25 Risk UI exposes risk score without rendering raw responses", () => {
  assert.match(riskPage, /Risk score:/);
  assert.match(riskPage, /matched_signals/);
  assert.doesNotMatch(riskPage, /result\.response\b/);
});

