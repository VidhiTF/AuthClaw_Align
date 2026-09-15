import assert from "node:assert/strict";
import test from "node:test";

import { csvCell, formatDateTime } from "../src/lib/ui-format.ts";

test("formatDateTime renders timestamps in IST", () => {
  assert.equal(formatDateTime("2026-07-09T10:35:10Z"), "Jul 9, 2026, 04:05:10 PM");
});

test("audit CSV cells escape structure and neutralize spreadsheet formulas", () => {
  for (const value of ["=1+1", "+1", "-1", "@SUM(A1)", "\t=1", "\r=1", "\n=1", " =1", "\u0000=1", "\u200b=1", "＝1", "＋1", "－1", "＠SUM(A1)"]) {
    assert.equal(csvCell(value), `"'${value.replaceAll('"', '""')}"`);
  }
  for (const [value, expected] of [[null, '""'], [undefined, '""'], [200, '"200"'], ["gpt-4o-mini", '"gpt-4o-mini"'], ['a,"b"\r\nc', '"a,""b""\r\nc"'], ['x",=1', '"x"",=1"']]) {
    assert.equal(csvCell(value), expected);
  }
});
