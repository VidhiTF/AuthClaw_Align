import assert from "node:assert/strict";
import test from "node:test";

import { formatDateTime } from "../src/lib/ui-format.ts";

test("formatDateTime renders timestamps in IST", () => {
  assert.equal(formatDateTime("2026-07-09T10:35:10Z"), "Jul 9, 2026, 04:05:10 PM");
});
