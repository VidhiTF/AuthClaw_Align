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

test("auditor trust summaries preserve unassessed scores as Unknown", () => {
  const library = compile("../src/lib/trust-summary.ts", {});
  const component = compile("../src/components/trust-summary.tsx", {
    require: (name: string) => name === "@/lib/trust-summary" ? library : require(name),
  });
  const html = renderToStaticMarkup(React.createElement(component.TrustSummary as React.ComponentType<{ summary: unknown }>, { summary: {
    generated_at: "2026-09-18T00:00:00Z", counts: { verified: 0, in_progress: 0, planned: 1 }, verified: [], in_progress: [],
    planned: [{ id: "CC6.1", framework: "SOC2", name: "Unassessed access control", score: null, status: "insufficient_evidence" }],
  } }));
  assert.match(html, /Unassessed access control/); assert.match(html, /Unknown/);
  assert.doesNotMatch(html, />%<|null%|0%/);
});

test("overview clears stale values after an outage and renders an explicit alert", async () => {
  const states: unknown[] = [], refs: Array<{ current: unknown }> = [];
  let cursor = 0, refCursor = 0, refresh: () => Promise<void>, failed = false;
  let failedSource = "", health = "healthy", auditHealth = "healthy", score: number | null = 72;
  let delayed = false;
  const pending: Array<() => void> = [];
  const react = { ...React,
    useState: (initial: unknown) => { const index = cursor++; if (!(index in states)) states[index] = initial;
      return [states[index], (value: unknown) => { states[index] = value; }]; },
    useRef: (initial: unknown) => refs[refCursor++] ?? (refs[refCursor - 1] = { current: initial }),
    useCallback: (callback: () => Promise<void>) => (refresh = callback), useEffect: () => {},
  };
  const page = compile("../src/app/(console)/overview/page.tsx", {
    require: (name: string) => name === "react" ? react : name === "@/lib/trust-summary" ? compile("../src/lib/trust-summary.ts", {})
      : name === "@/lib/ui-format" ? compile("../src/lib/ui-format.ts", {}) : name === "next/link"
      ? ({ children, ...props }: React.PropsWithChildren) => React.createElement("a", props, children) : require(name),
    fetch: async (url: string) => {
      const unavailable = failed || !!failedSource && url.includes(failedSource);
      const response = { ok: !unavailable, status: unavailable ? 503 : 200,
        json: async () => url.includes("dashboard") ? { status: health, totalRequests: 12345, redactions24h: 0, openApprovals: 0,
          coverageReason: "Gateway collection coverage is unverified.", metricStates: { p99LatencyMs: "unknown" }, sources: { audit: { status: auditHealth } }, recentActivity: [] }
          : { generated_at: "2026-09-18T00:00:00Z", frameworks: [{ framework: "SOC2", score, readiness_level: "insufficient_evidence", metrics: { evidence_count: 0, open_findings: 0 } }] } };
      if (delayed) await new Promise<void>((resolve) => pending.push(resolve));
      return response;
    },
  });
  const render = () => { cursor = 0; refCursor = 0; return renderToStaticMarkup(React.createElement(page.default as React.ComponentType)); };
  render(); await refresh!(); assert.match(render(), /12345/);
  assert.match(render(), /Gateway collection coverage is unverified/);
  failedSource = "compliance-scores"; await refresh!();
  assert.match(render(), /12345/); assert.match(render(), /Current compliance assessment unavailable/);
  failedSource = "dashboard"; await refresh!();
  assert.doesNotMatch(render(), /12345/); assert.match(render(), /72%/);
  failedSource = "";
  for (health of ["healthy", "degraded", "unknown", "unavailable", "not_applicable"]) {
    await refresh!(); assert.match(render(), new RegExp(`Telemetry ${health}`));
    assert.match(render(), /No recent audit activity\./, "A successful empty activity source must survive another source's failure");
  }
  auditHealth = "unknown"; await refresh!();
  assert.match(render(), /Audit activity unknown/); assert.match(render(), /Audit activity coverage is unverified/);
  assert.doesNotMatch(render(), /No recent audit activity/);
  health = "unavailable"; await refresh!();
  assert.match(render(), /Audit activity unknown/, "Another source's failure must not change the audit source state");
  health = "unknown"; score = null; await refresh!();
  assert.doesNotMatch(render(), /null%/); assert.match(render(), /Unknown/);
  delayed = true; const staleRefresh = refresh!();
  assert.doesNotMatch(render(), /12345/, "Pending refresh must not relabel old-window totals as current observations");
  delayed = false; failed = true; await refresh!();
  pending.forEach((resolve) => resolve()); await staleRefresh;
  const html = render();
  assert.match(html, /role="alert"/); assert.match(html, /Telemetry unavailable/);
  assert.match(html, /Unknown/); assert.doesNotMatch(html, /12345|Active Engine|System Live|Telemetry loaded/);
  if (process.env.ENT019_DASHBOARD_EXPORT) fs.writeFileSync(process.env.ENT019_DASHBOARD_EXPORT,
    `<!doctype html><meta charset="utf-8"><title>ENT-019 synthetic outage dashboard export</title>${html}`);
});

test("dashboard honors canonical coverage and state, independent of audit mirror serialization", async () => {
  const metrics = { source: "postgres", status: "healthy", complete: true, totalRequests: 201, redactions24h: 1,
    requestsPerSec: 201 / 86400, p99LatencyMs: 0, windowStart: "2026-09-17T00:00:00Z", windowEnd: "2026-09-18T00:00:00Z" };
  let auditSource = "postgres", failure = "", malformed = "", emptyAudit = false, approvalComplete = true;
  const calls: string[] = [];
  const route = compile("../src/app/api/dashboard/route.ts", {
    require: (name: string) => name === "next/server" ? { NextResponse: { json: (body: unknown) => body } } : {
      getSessionContext: async () => ({ session: { apiKey: "synthetic" } }),
      handleApiError: () => ({ status: "unavailable" }),
    }, process: { env: {} }, URL,
    fetch: async (url: string) => {
      calls.push(url);
      if (url.includes(failure) && failure) throw new Error("synthetic outage");
      return { ok: true, json: async () => url.includes(malformed) && malformed ? {} : url.includes("approvals/pending-count") ? { count: 61, complete: approvalComplete }
        : url.includes("/metrics?") ? metrics : { source: auditSource, total: emptyAudit ? 0 : 409, records: emptyAudit ? [] : [{
          record_id: "record-1", timestamp: "2026-09-18T00:00:00Z", actor_type: "gateway", request_id: "request-1",
          idempotency_key: auditSource === "postgres" ? "gateway:request-1:provider_outcome" : "record-1", action: "allow", duration_ms: 20,
        }] } };
    },
  });
  const request = { url: "http://local/api/dashboard" };
  for (auditSource of ["postgres", "clickhouse"]) {
    const result = await route.GET(request) as typeof metrics & { openApprovals: number; recentActivity: unknown[]; sources: Record<string, { status: string }> };
    assert.equal(result.totalRequests, 201); assert.equal(result.redactions24h, 1);
    assert.equal(result.requestsPerSec, 201 / 86400); assert.equal(result.p99LatencyMs, 0);
    assert.equal(result.openApprovals, 61);
    assert.equal(result.status, auditSource === "postgres" ? "healthy" : "unknown");
    assert.equal(result.sources.audit.status, auditSource === "postgres" ? "healthy" : "unknown");
    assert.equal(result.recentActivity.length, 1, "Unverified coverage must not hide observed events");
  }
  emptyAudit = true;
  const stalled = await route.GET(request) as typeof metrics & { sources: Record<string, { status: string }>; recentActivity: unknown[] };
  assert.equal(stalled.status, "unknown"); assert.equal(stalled.sources.audit.status, "unknown");
  assert.equal(stalled.totalRequests, 201, "PostgreSQL observations survive an empty reachable audit mirror");
  assert.equal(stalled.recentActivity.length, 0);
  auditSource = "postgres";
  assert.equal((await route.GET(request) as { status: string }).status, "healthy", "An authoritative empty result is valid");
  emptyAudit = false; auditSource = "clickhouse";
  assert.ok(calls.some((url) => url.endsWith("/audit-logs/metrics?hours=24")));
  assert.ok(calls.some((url) => url.endsWith("/audit-logs?limit=8")));
  for (const source of ["approvals", "/metrics?", "audit-logs?limit"]) {
    failure = source;
    const result = await route.GET(request) as { status: string; openApprovals: number | null; totalRequests: number | null; sources: Record<string, { status: string }> };
    assert.equal(result.status, "unavailable");
    assert.equal(result.openApprovals, source === "approvals" ? null : 61);
    assert.equal(result.totalRequests, source === "/metrics?" ? null : 201);
    assert.equal(Object.values(result.sources).filter((item) => item.status === "unavailable").length, 1);
  }
  failure = ""; malformed = "/metrics?";
  const malformedResult = await route.GET(request) as { totalRequests: number | null; openApprovals: number };
  assert.equal(malformedResult.totalRequests, null); assert.equal(malformedResult.openApprovals, 61);
  malformed = ""; approvalComplete = false;
  const incompleteApprovals = await route.GET(request) as { status: string; openApprovals: number | null; sources: Record<string, { status: string }> };
  assert.equal(incompleteApprovals.status, "unknown"); assert.equal(incompleteApprovals.openApprovals, null);
  assert.equal(incompleteApprovals.sources.approvals.status, "unknown");
  approvalComplete = true; malformed = "approvals/pending-count";
  const malformedApprovals = await route.GET(request) as { status: string; openApprovals: number | null; sources: Record<string, { status: string }> };
  assert.equal(malformedApprovals.status, "unavailable"); assert.equal(malformedApprovals.openApprovals, null);
  assert.equal(malformedApprovals.sources.approvals.status, "unavailable");
  malformed = "";
  Object.assign(metrics, { p99LatencyMs: null });
  const noLatency = await route.GET(request) as { status: string; metricStates: Record<string, string>; totalRequests: number };
  assert.equal(noLatency.status, "unknown"); assert.equal(noLatency.metricStates.p99LatencyMs, "unknown");
  assert.equal(noLatency.totalRequests, 201);
  for (const state of ["unknown", "degraded", "unavailable", "not_applicable"]) {
    Object.assign(metrics, { status: state, complete: false, totalRequests: 201 });
    const incomplete = await route.GET(request) as { totalRequests: number | null; metricStates: Record<string, string>; sources: Record<string, { status: string }> };
    assert.equal(incomplete.totalRequests, null, "Incomplete persisted rows must never become a total traffic count");
    assert.equal(incomplete.sources.gateway.status, state);
    assert.equal(incomplete.metricStates.totalRequests, state);
  }
});

test("compliance score and history failures render unknown inputs; recovery preserves measured zero", async () => {
  const states: unknown[] = [], refs: Array<{ current: unknown }> = [];
  let cursor = 0, refCursor = 0, callbacks: Array<() => Promise<void>> = [], failedSource = "";
  const history: Array<{ framework: string; snapshot_date: string; overall_score: number | null }> = [];
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
    require: (name: string) => name === "react" ? react : name === "@/lib/trust-summary" ? compile("../src/lib/trust-summary.ts", {})
      : name === "@/lib/clipboard" ? { flashCopy: () => {} }
      : name === "@/lib/errors" ? { getErrorMessage: (error: Error) => error.message }
      : name === "@/lib/ui-format" ? { readinessLabel: (value: string) => value }
      : name === "@/components/trust-summary" ? { TrustSummary: () => null } : require(name),
    fetch: async (url: string) => ({ ok: !failedSource || !url.includes(failedSource), status: failedSource && url.includes(failedSource) ? 503 : 200,
      json: async () => url.includes("history") ? { items: history } : scores }),
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
    assert.match(html, /Score history unavailable/); assert.match(html, /Current compliance assessment unavailable/);
    assert.doesNotMatch(html, /No score snapshots yet|animate-spin|0 controls/);
    assert.doesNotMatch(html, /style="width:0%"/);
    failedSource = ""; await callbacks[0]();
    assert.match(render(), /Redaction Records<\/span><span[^>]*>0<\/span>/);
  }
  Object.assign(scores.frameworks[0], { score: null, controls: [{ id: "CC6.1", name: "Access", score: null,
    status: "insufficient_evidence", evidence: [], gaps: [] }] });
  history.push({ framework: "SOC2", snapshot_date: "2026-09-18", overall_score: null });
  await callbacks[0]();
  const unknown = render();
  assert.match(unknown, /text-slate-500[^>]*>INSUFFICIENT EVIDENCE - Unknown/);
  assert.match(unknown, /30-Day Score History[\s\S]*Unknown/);
  assert.doesNotMatch(unknown, /null%|42%/);
  assert.doesNotMatch(unknown, /style="width:0%"/);
  Object.assign(scores.frameworks[0], { score: 0 });
  await callbacks[0]();
  assert.match(render(), /style="width:0%"/, "Measured zero retains its progress bar");
});

test("public Trust Center renders score provenance and unknown legacy metadata", async () => {
  const states: unknown[] = [];
  let cursor = 0, load: (access: string) => Promise<void>;
  const scores = { overall_score: null, readiness_level: "insufficient_evidence", frameworks: [{
    framework: "SOC2", score: null as number | null, readiness_level: "insufficient_evidence", controls: [], metrics: {},
  }],
    calculation_version: "evidence-v2", evidence_timestamp: "2026-09-18T06:00:00Z",
    missing_control_treatment: "Unassessed controls remain unknown", generated_at: "2026-09-21T00:00:00Z" };
  const react = { ...React,
    useState: (initial: unknown) => { const index = cursor++; if (!(index in states)) states[index] = initial;
      return [states[index], (value: unknown) => { states[index] = value; }]; },
    useRef: () => ({ current: null }), useEffect: () => {}, useMemo: (callback: () => unknown) => callback(),
    useCallback: (callback: typeof load) => (load = callback),
  };
  const page = compile("../src/app/trust-center/[token]/page.tsx", {
    require: (name: string) => name === "react" ? react : name === "next/navigation" ? { useParams: () => ({ token: "fixture" }) }
      : name === "@/lib/trust-summary" ? compile("../src/lib/trust-summary.ts", {})
      : name === "@/components/trust-summary" ? { TrustSummary: () => null } : require(name),
    fetch: async () => ({ ok: true, json: async () => ({ scores, tenant: { name: "Fixture" },
      share: { frameworks: ["SOC2"], expires_at: "2026-10-01T00:00:00Z" }, generated_at: scores.generated_at, verification_guide: [] }) }),
  });
  const render = () => { cursor = 0; return renderToStaticMarkup(React.createElement(page.default as React.ComponentType)); };
  render(); await load!("fixture-access");
  assert.match(render(), /Evidence timestamp: 2026-09-18T06:00:00Z/);
  assert.match(render(), /Missing-control treatment: Unassessed controls remain unknown/);
  assert.doesNotMatch(render(), /rounded-full bg-slate-800 overflow-hidden/);
  scores.frameworks[0].score = 0;
  await load!("fixture-access");
  assert.match(render(), /style="width:0%"/);
  Object.assign(scores, { evidence_timestamp: null, missing_control_treatment: undefined });
  await load!("fixture-access");
  assert.match(render(), /Evidence timestamp: Unknown/);
  assert.match(render(), /Missing-control treatment: Unknown/);
});
