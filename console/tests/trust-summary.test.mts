import assert from "node:assert/strict";
import test from "node:test";

import { calculationVersion, evidenceAssessmentLabel, scoreHistoryEntries, trustSummarySections, type TrustSummary } from "../src/lib/trust-summary.ts";

const summary: TrustSummary = {
  generated_at: "2026-07-16T00:00:00+00:00",
  counts: { verified: 1, in_progress: 1, planned: 1 },
  verified: [{ framework: "SOC2", id: "one", name: "One", score: 90, status: "compliant" }],
  in_progress: [{ framework: "GDPR", id: "two", name: "Two", score: 70, status: "partial" }],
  planned: [{ framework: "HIPAA", id: "three", name: "Three", score: 40, status: "non_compliant" }],
};

test("trust summary exposes the three backend-provided rendering sections", () => {
  const sections = trustSummarySections(summary);
  assert.deepEqual(sections.map((section) => section.label), ["Verified", "In Progress", "Planned"]);
  assert.deepEqual(sections.map((section) => section.controls[0]?.id), ["one", "two", "three"]);
});

test("trust summary renders empty backend buckets without classifying controls", () => {
  const sections = trustSummarySections({
    ...summary,
    counts: { verified: 0, in_progress: 0, planned: 0 },
    verified: [], in_progress: [], planned: [],
  });
  assert.ok(sections.every((section) => section.controls.length === 0));
});

test("missing trust summary remains compatible", () => {
  const sections = trustSummarySections();
  assert.ok(sections.every((section) => section.controls.length === 0));
});

test("absent and blank calculation versions stay explicitly legacy", () => {
  assert.equal(calculationVersion(), "legacy_unversioned");
  assert.equal(calculationVersion(" "), "legacy_unversioned");
  assert.equal(calculationVersion("evidence-v2"), "evidence-v2");
});

test("evidence presentation preserves a blocked server decision even with high counts", () => {
  assert.equal(evidenceAssessmentLabel({
    state: "blocked", reason_codes: ["open_finding"], required_count: 1, qualified_count: 1,
    as_of: "2026-09-18T00:00:00Z", valid_until: null,
  }), "Evidence blocked: 1/1 requirements qualified");
  assert.match(evidenceAssessmentLabel(), /unavailable.*legacy/);
});

test("same-day versions have separate identities and a method-change boundary", () => {
  const entries = scoreHistoryEntries([
    { framework: "SOC2", snapshot_date: "2026-09-18", calculation_version: "evidence-v2" },
    { framework: "GDPR", snapshot_date: "2026-09-18" },
    { framework: "SOC2", snapshot_date: "2026-09-18" },
    { framework: "SOC2", snapshot_date: "2026-09-17" },
  ]);
  assert.equal(new Set(entries.map(({ key }) => key)).size, 4);
  assert.deepEqual(entries.map(({ methodChanged }) => methodChanged), [false, false, true, false]);
  assert.equal(entries[2].version, "legacy_unversioned");
});

test("history rendering preserves server order and authoritative snapshot ids", () => {
  const item = { id: "snapshot-one", framework: "SOC2", snapshot_date: "2026-09-18", calculation_version: "evidence-v2" };
  const entries = scoreHistoryEntries([item]);
  assert.equal(entries[0].key, "snapshot-one");
  assert.equal(entries[0].item, item);
});
