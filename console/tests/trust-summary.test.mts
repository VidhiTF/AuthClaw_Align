import assert from "node:assert/strict";
import test from "node:test";

import { trustSummarySections, type TrustSummary } from "../src/lib/trust-summary.ts";

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
