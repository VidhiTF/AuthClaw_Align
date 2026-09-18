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
  let payload: unknown = { records: [{ duration_ms: 0, duration: 42, timestamp: new Date().toISOString() }] };
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
    { duration_ms: 10, timestamp: new Date().toISOString() },
    { duration_ms: 20, timestamp: new Date(Date.now() - 1000).toISOString() },
  ] };
  const sampled = await route.GET(request) as { p99LatencyMs: number; requestsPerSec: number };
  assert.equal(sampled.p99LatencyMs, 20); assert.equal(sampled.requestsPerSec, 2);
  payload = {}; assert.equal((await route.GET(request) as { status: string }).status, "unavailable");
  payload = { records: [{ timestamp: "invalid" }] };
  assert.equal((await route.GET(request) as { status: string }).status, "unavailable");
  ok = false; assert.equal((await route.GET(request) as { status: string }).status, "unavailable");
});
