import assert from "node:assert/strict";
import fs from "node:fs";
import { createRequire } from "node:module";
import test from "node:test";
import vm from "node:vm";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import ts from "typescript";

const require = createRequire(import.meta.url);
function compile(path: string, overrides: Record<string, unknown>) {
  const source = fs.readFileSync(new URL(path, import.meta.url), "utf8");
  const exports = {};
  vm.runInNewContext(ts.transpileModule(source, { compilerOptions: {
    module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true,
  } }).outputText, { exports, require, console, AbortSignal, ...overrides });
  return exports as Record<string, (...args: unknown[]) => unknown>;
}

test("overview clears stale values after an outage and renders an explicit alert", async () => {
  const states: unknown[] = [], refs: Array<{ current: unknown }> = [];
  let cursor = 0, refCursor = 0, refresh: () => Promise<void>, failed = false;
  let delayed = false;
  const pending: Array<() => void> = [];
  const react = { ...React,
    useState: (initial: unknown) => { const index = cursor++; if (!(index in states)) states[index] = initial;
      return [states[index], (value: unknown) => { states[index] = value; }]; },
    useRef: (initial: unknown) => refs[refCursor++] ?? (refs[refCursor - 1] = { current: initial }),
    useCallback: (callback: () => Promise<void>) => (refresh = callback), useEffect: () => {},
  };
  const page = compile("../src/app/(console)/overview/page.tsx", {
    require: (name: string) => name === "react" ? react : name === "next/link"
      ? ({ children, ...props }: React.PropsWithChildren) => React.createElement("a", props, children) : require(name),
    fetch: async (url: string) => {
      const response = { ok: !failed, status: failed ? 503 : 200,
        json: async () => url.includes("dashboard") ? { totalRequests: 12345, redactions24h: 0, openApprovals: 0, recentActivity: [] } : { frameworks: [] } };
      if (delayed) await new Promise<void>((resolve) => pending.push(resolve));
      return response;
    },
  });
  const render = () => { cursor = 0; refCursor = 0; return renderToStaticMarkup(React.createElement(page.default as React.ComponentType)); };
  render(); await refresh!(); assert.match(render(), /12345/);
  delayed = true; const staleRefresh = refresh!();
  delayed = false; failed = true; await refresh!();
  pending.forEach((resolve) => resolve()); await staleRefresh;
  const html = render();
  assert.match(html, /role="alert"/); assert.match(html, /Telemetry unavailable/);
  assert.match(html, /Unknown/); assert.doesNotMatch(html, /12345|Active Engine|System Live|Telemetry loaded/);
  if (process.env.ENT019_DASHBOARD_EXPORT) fs.writeFileSync(process.env.ENT019_DASHBOARD_EXPORT,
    `<!doctype html><meta charset="utf-8"><title>ENT-019 synthetic outage dashboard export</title>${html}`);
});

test("dashboard BFF rejects outages and malformed payloads; measured zero latency remains zero", async () => {
  const outcome = { actor_type: "gateway", request_id: "request-1", idempotency_key: "gateway:request-1:provider_outcome" };
  let payload: unknown = { records: [{ ...outcome, duration_ms: 0, duration: 42, timestamp: new Date().toISOString() }] };
  let ok = true;
  const route = compile("../src/app/api/dashboard/route.ts", {
    require: (name: string) => name === "next/server" ? { NextResponse: { json: (body: unknown) => body } } : {
      getSessionContext: async () => ({ session: { apiKey: "synthetic" } }),
      handleApiError: () => ({ status: "unavailable" }),
    }, process: { env: {} }, URL,
    fetch: async (url: string) => ({ ok, json: async () => url.includes("approvals") ? [] : payload }),
  });
  const request = { url: "http://local/api/dashboard" };
  assert.equal((await route.GET(request) as { p99LatencyMs: number }).p99LatencyMs, 0);
  payload = { records: [
    { ...outcome, duration_ms: 10, timestamp: new Date().toISOString() },
    { ...outcome, duration_ms: 20, timestamp: new Date(Date.now() - 1000).toISOString() },
  ] };
  const sampled = await route.GET(request) as { p99LatencyMs: number; requestsPerSec: number };
  assert.equal(sampled.p99LatencyMs, 20); assert.equal(sampled.requestsPerSec, 2);
  for (const metadata of [
    { actor_type: "backend", action: "remediation_completed" },
    { ...outcome, idempotency_key: "gateway:request-1:provider_attempt" },
    { ...outcome, idempotency_key: "gateway:request-1:decision:block" },
    {},
  ]) {
    payload = { records: [{ ...metadata, duration_ms: 0, timestamp: new Date().toISOString() }] };
    assert.equal((await route.GET(request) as { p99LatencyMs: number | null }).p99LatencyMs, null,
      "Unmeasured audit placeholders must not become gateway latency");
  }
  payload = {}; assert.equal((await route.GET(request) as { status: string }).status, "unavailable");
  payload = { records: [{ timestamp: "invalid" }] };
  assert.equal((await route.GET(request) as { status: string }).status, "unavailable");
  ok = false; assert.equal((await route.GET(request) as { status: string }).status, "unavailable");
});

test("compliance score and history failures render unknown inputs; recovery preserves measured zero", async () => {
  const states: unknown[] = [], refs: Array<{ current: unknown }> = [];
  let cursor = 0, refCursor = 0, callbacks: Array<() => Promise<void>> = [], failedSource = "";
  const react = { ...React,
    useState: (initial: unknown) => { const index = cursor++; if (!(index in states)) states[index] = initial;
      return [states[index], (value: unknown) => { states[index] = value; }]; },
    useRef: (initial: unknown) => refs[refCursor++] ?? (refs[refCursor - 1] = { current: initial }),
    useCallback: (callback: () => Promise<void>) => { callbacks.push(callback); return callback; },
    useMemo: (callback: () => unknown) => callback(), useEffect: () => {},
  };
  const scores = { generated_at: "2026-09-18T00:00:00Z", frameworks: [{ framework: "SOC2", score: 42,
    generated_at: "2026-09-18T00:00:00Z", readiness_level: "needs_attention", controls: [],
    metrics: { evidence_count: 2, audit_event_count: 5, audit_hash_count: 5, redaction_count: 0, open_findings: 7, critical_findings: 3 } }] };
  const page = compile("../src/app/(console)/compliance/page.tsx", {
    require: (name: string) => name === "react" ? react : name === "@/lib/clipboard" ? { flashCopy: () => {} }
      : name === "@/lib/errors" ? { getErrorMessage: (error: Error) => error.message }
      : name === "@/lib/ui-format" ? { readinessLabel: (value: string) => value }
      : name === "@/components/trust-summary" ? { TrustSummary: () => null } : require(name),
    fetch: async (url: string) => ({ ok: !failedSource || !url.includes(failedSource), status: failedSource && url.includes(failedSource) ? 503 : 200,
      json: async () => url.includes("history") ? { items: [] } : scores }),
  });
  const render = () => { cursor = 0; refCursor = 0; callbacks = [];
    return renderToStaticMarkup(React.createElement(page.default as React.ComponentType)); };
  for (const source of ["persist_snapshot", "history"]) {
    render(); await callbacks[0]();
    assert.match(render(), /Open Findings<\/span><span[^>]*>7<\/span>/);
    failedSource = source; await callbacks[0]();
    const html = render();
    for (const label of ["Open Findings", "Critical Findings", "Evidence Records", "Redaction Records"])
      assert.match(html, new RegExp(`${label}</span><span[^>]*>Unknown</span>`));
    assert.match(html, /Score history unavailable/); assert.match(html, /Control scores unavailable/);
    assert.doesNotMatch(html, /No score snapshots yet|animate-spin|0 controls/);
    failedSource = ""; await callbacks[0]();
    assert.match(render(), /Redaction Records<\/span><span[^>]*>0<\/span>/);
  }
});
