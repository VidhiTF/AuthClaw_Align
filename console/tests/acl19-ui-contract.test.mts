import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";


const root = path.resolve(import.meta.dirname, "..");
const compliancePage = fs.readFileSync(
  path.join(root, "src", "app", "(console)", "compliance", "page.tsx"),
  "utf8",
);
const evidencePage = fs.readFileSync(
  path.join(root, "src", "app", "(console)", "evidence", "page.tsx"),
  "utf8",
);


test("ACL-19 compliance UI exposes ownership and evidence-source metadata", () => {
  assert.match(compliancePage, /Product owner:/);
  assert.match(compliancePage, /Operational owner:/);
  assert.match(compliancePage, /Mapped Evidence Sources/);
  assert.match(compliancePage, /Collection frequency/);
});


test("ACL-19 compliance UI makes open exceptions visibly block compliance", () => {
  assert.match(compliancePage, /Open Exceptions — compliance blocked/);
  assert.match(compliancePage, /control\.exceptions/);
});


test("ACL-19 evidence UI exposes integrity verification metadata", () => {
  assert.match(evidencePage, /Integrity Metadata/);
  assert.match(evidencePage, /integrity_verified/);
  assert.match(evidencePage, /integrity_hash/);
  assert.match(evidencePage, /integrity_version/);
});
