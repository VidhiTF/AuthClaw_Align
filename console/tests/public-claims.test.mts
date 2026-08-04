import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const scanner = path.resolve(import.meta.dirname, "..", "scripts", "check-public-claims.mjs");

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "authclaw-claims-"));
  const consoleRoot = path.join(root, "console");
  fs.mkdirSync(path.join(root, "docs", "compliance"), { recursive: true });
  fs.mkdirSync(path.join(consoleRoot, "src", "marketing"), { recursive: true });
  fs.mkdirSync(path.join(consoleRoot, "src", "app", "trust-center", "[token]"), { recursive: true });
  fs.mkdirSync(path.join(consoleRoot, "src", "app", "(marketing)", "demo"), { recursive: true });
  fs.writeFileSync(path.join(root, "docs", "compliance", "PUBLIC_CLAIM_REGISTER.md"),
    "| CLM-001 |\n| CLM-002 |\n| CLM-003 |\n| CLM-004 |\n| CLM-006 |\n| CLM-014 |\n");
  fs.writeFileSync(path.join(root, "docs", "compliance", "ACL-35_PUBLIC_CLAIMS_APPROVAL.md"),
    "docs/COMPLIANCE_BOUNDARY.md\ngateway and agent redaction tests\naudit-store tests\nevidence-supported readiness indicators\nindependent CPA firm\nautomated framework-scoring criteria\n");
  fs.writeFileSync(path.join(consoleRoot, "src", "marketing", "claims.ts"),
    "technical controls that support GDPR obligations and SOC 2 readiness; configured sensitive-data patterns can be detected and redacted before model-provider egress; signed evidence export; automated framework scoring; not an independent SOC 2 Type II report or a SOC 3 report; no certification is implied");
  fs.writeFileSync(path.join(consoleRoot, "src", "app", "trust-center", "[token]", "page.tsx"),
    "X-Trust-Center-Access control.evidence /signed-export Upload and Verify");
  fs.writeFileSync(path.join(consoleRoot, "src", "app", "(marketing)", "demo", "page.tsx"),
    'requestedAccess="DEMO" sourcePage="/demo"');
  return consoleRoot;
}

function scan(cwd: string) {
  return spawnSync(process.execPath, [scanner], { cwd, encoding: "utf8" });
}

test("claim scanner skips a missing optional root and scans existing roots", () => {
  const cwd = fixture();
  const result = scan(cwd);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "Public claim scan passed.\n");
});

test("claim scanner still fails invalid claims with unchanged output", () => {
  const cwd = fixture();
  fs.appendFileSync(path.join(cwd, "src", "marketing", "claims.ts"), "\ntamper-proof");
  const result = scan(cwd);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /^Unsupported public compliance claims found:\n/);
  assert.match(result.stderr, /src[\\/]marketing[\\/]claims\.ts:2: tamper-proof guarantee: "tamper-proof"/);
});
