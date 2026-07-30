"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { CheckCircle2, ExternalLink, FileText, Play, ShieldAlert, Sparkles, XCircle } from "lucide-react";

interface Probe {
  id: string;
  name: string;
  category: string;
  prompt: string;
  severity: "critical" | "high" | "medium" | "low";
  risk_score: number;
}

interface ProbeResult extends Probe {
  probe_id: string;
  status: "pass" | "fail";
  policy_decision: string;
  response_status: string;
  reason: string;
  case_severity: "critical" | "high" | "medium" | "low";
  severity_rank: number;
  risk_score: number;
  matched_signals: string[];
}

interface RedTeamRun {
  workflow_id: string;
  posture: string;
  passed: number;
  failed: number;
  simulation_only: boolean;
  results: ProbeResult[];
  completed_at: string | null;
}

interface RedTeamState {
  latest: RedTeamRun | null;
  runs: RedTeamRun[];
  probes: Probe[];
}

const emptyState: RedTeamState = { latest: null, runs: [], probes: [] };

function badgeClass(status: string) {
  if (status === "pass" || status === "go") return "border-emerald-600/30 bg-emerald-50 text-emerald-700";
  if (status === "fail" || status === "no_go") return "border-red-600/30 bg-red-50 text-red-700";
  return "border-[#E6E9F0] bg-[#F5F7FA] text-[#475069]";
}

function severityClass(severity: string) {
  if (severity === "critical") return "border-red-600/30 bg-red-50 text-red-700";
  if (severity === "high") return "border-amber-600/30 bg-amber-50 text-amber-700";
  if (severity === "medium") return "border-yellow-600/30 bg-yellow-50 text-yellow-700";
  return "border-blue-600/30 bg-blue-50 text-blue-700";
}

export default function RiskPage() {
  const [data, setData] = useState<RedTeamState>(emptyState);
  const [responses, setResponses] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [simulationOnly, setSimulationOnly] = useState(true);

  const load = async () => {
    setError(null);
    try {
      const res = await fetch("/api/red-team");
      const body = await res.json();
      if (!res.ok) throw new Error(body.error || "Failed to load red-team runs");
      setData(body);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load red-team runs");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void load();
    }, 0);
    return () => window.clearTimeout(timer);
  }, []);

  const run = async () => {
    setRunning(true);
    setError(null);
    try {
      const observed_responses = Object.fromEntries(Object.entries(responses).filter(([, value]) => value.trim()));
      const res = await fetch("/api/red-team", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ observed_responses, simulation_only: simulationOnly }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error || "Red-team run failed");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Red-team run failed");
    } finally {
      setRunning(false);
    }
  };

  const latest = data.latest;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <p className="text-sm font-semibold uppercase tracking-wider text-indigo-700">Risk & Red Teaming</p>
          <h1 className="mt-2 text-3xl font-bold tracking-tight text-[#0E1726]">Risk Command Center</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-[#475069]">
            Run adversarial AI-control probes. Failed probes create RED_TEAM evidence and findings; no cloud resources or customer data are changed in simulation mode.
          </p>
        </div>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
          <label className="inline-flex items-center gap-2 rounded-lg border border-[#D8DEEA] bg-white px-3 py-2 text-sm font-semibold text-[#0E1726] shadow-sm">
            <input
              type="checkbox"
              checked={simulationOnly}
              onChange={(event) => setSimulationOnly(event.target.checked)}
              className="h-4 w-4 accent-indigo-600"
            />
            Simulation only
          </label>
          <button
            onClick={run}
            disabled={running}
            className="inline-flex items-center justify-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-lg shadow-indigo-900/20 transition-colors hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-60"
          >
            <Play className="h-4 w-4" />
            {running ? "Running" : simulationOnly ? "Run Safe Simulation" : "Run Live Probes"}
          </button>
        </div>
      </div>
      {!simulationOnly && (
        <div className="rounded-lg border border-amber-500/30 bg-amber-50 px-4 py-3 text-sm font-semibold text-amber-800">
          Live red-team mode is blocked unless the backend explicitly enables AUTHCLAW_RED_TEAM_LIVE_ENABLED=true. Simulation remains the safe default.
        </div>
      )}

      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-50 px-4 py-3 text-sm font-semibold text-red-700">{error}</div>
      )}

      <div className="grid gap-4 md:grid-cols-3">
        <div className="rounded-lg border border-[#E6E9F0] bg-white p-5">
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-indigo-700" />
            <p className="text-xs font-semibold uppercase tracking-wider text-[#6B7488]">1. Test</p>
          </div>
          <p className="mt-2 text-sm font-semibold text-[#0E1726]">Red Teaming attacks AI controls with safe probes.</p>
        </div>
        <Link href="/findings?framework=RED_TEAM" className="rounded-lg border border-[#E6E9F0] bg-white p-5 transition-colors hover:border-indigo-500/50">
          <div className="flex items-center gap-2">
            <FileText className="h-4 w-4 text-indigo-700" />
            <p className="text-xs font-semibold uppercase tracking-wider text-[#6B7488]">2. Track</p>
          </div>
          <p className="mt-2 inline-flex items-center gap-2 text-sm font-semibold text-[#0E1726]">
            Failures become findings <ExternalLink className="h-4 w-4" />
          </p>
        </Link>
        <Link href="/agent" className="rounded-lg border border-[#E6E9F0] bg-white p-5 transition-colors hover:border-indigo-500/50">
          <div className="flex items-center gap-2">
            <Sparkles className="h-4 w-4 text-indigo-700" />
            <p className="text-xs font-semibold uppercase tracking-wider text-[#6B7488]">3. Fix</p>
          </div>
          <p className="mt-2 inline-flex items-center gap-2 text-sm font-semibold text-[#0E1726]">
            Agent explains and prepares remediation <ExternalLink className="h-4 w-4" />
          </p>
        </Link>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <div className="rounded-lg border border-[#E6E9F0] bg-white p-5">
          <p className="text-xs font-semibold uppercase tracking-wider text-[#6B7488]">Posture</p>
          <p className={`mt-3 inline-flex rounded-md border px-2.5 py-1 text-sm font-semibold ${badgeClass(latest?.posture || "")}`}>
            {latest ? latest.posture.replace("_", "-").toUpperCase() : loading ? "LOADING" : "NO RUNS"}
          </p>
        </div>
        <div className="rounded-lg border border-[#E6E9F0] bg-white p-5">
          <p className="text-xs font-semibold uppercase tracking-wider text-[#6B7488]">Mode</p>
          <p className="mt-3 inline-flex rounded-md border border-indigo-600/30 bg-indigo-50 px-2.5 py-1 text-sm font-semibold text-indigo-700">
            {latest?.simulation_only === false ? "LIVE" : "SIMULATION"}
          </p>
        </div>
        <div className="rounded-lg border border-[#E6E9F0] bg-white p-5">
          <p className="text-xs font-semibold uppercase tracking-wider text-[#6B7488]">Passed</p>
          <p className="mt-2 text-2xl font-semibold text-emerald-700">{latest?.passed ?? 0}</p>
        </div>
        <div className="rounded-lg border border-[#E6E9F0] bg-white p-5">
          <p className="text-xs font-semibold uppercase tracking-wider text-[#6B7488]">Failed</p>
          <p className="mt-2 text-2xl font-semibold text-red-700">{latest?.failed ?? 0}</p>
        </div>
      </div>

      <div className="rounded-lg border border-[#E6E9F0] bg-white">
        <div className="border-b border-[#E6E9F0] px-5 py-4">
          <h2 className="text-base font-semibold text-[#0E1726]">Probe Set</h2>
          <p className="mt-1 text-sm text-[#6B7488]">Paste an observed target response when you have one. Empty responses are still scored against the active policy.</p>
        </div>
        <div className="divide-y divide-[#E6E9F0]">
          {data.probes.map((probe) => {
            const result = latest?.results.find((item) => item.probe_id === probe.id);
            return (
              <div key={probe.id} className="grid gap-4 p-5 lg:grid-cols-[1fr_1fr]">
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    {result?.status === "pass" ? <CheckCircle2 className="h-4 w-4 text-emerald-700" /> : <ShieldAlert className="h-4 w-4 text-[#6B7488]" />}
                    <h3 className="font-semibold text-[#0E1726]">{probe.name}</h3>
                    <span className="rounded-md border border-[#D8DEEA] bg-[#F5F7FA] px-2 py-0.5 text-xs font-semibold text-[#475069]">
                      {probe.category.replaceAll("_", " ")}
                    </span>
                    <span className={`rounded-md border px-2 py-0.5 text-xs font-semibold ${severityClass(probe.severity)}`}>
                      {probe.severity.toUpperCase()} · RANK {result?.severity_rank ?? "—"}
                    </span>
                    <span className={`rounded-md border px-2 py-0.5 text-xs font-semibold ${badgeClass(result?.status || "")}`}>
                      {result?.status?.toUpperCase() || "READY"}
                    </span>
                  </div>
                  <p className="mt-2 text-sm leading-6 text-[#6B7488]">{probe.prompt}</p>
                  {result && (
                    <div className="mt-2 space-y-1 text-xs text-[#6B7488]">
                      <p>{result.reason}</p>
                      <p>Risk score: {result.risk_score.toFixed(2)} · Matched signals: {result.matched_signals.join(", ") || "none"}</p>
                    </div>
                  )}
                </div>
                <textarea
                  value={responses[probe.id] || ""}
                  onChange={(event) => setResponses({ ...responses, [probe.id]: event.target.value })}
                  placeholder="Observed target response"
                  className="h-24 w-full resize-none rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] px-3 py-2 text-sm text-[#0E1726] outline-none transition-colors placeholder:text-[#6B7488] focus:border-indigo-500"
                />
              </div>
            );
          })}
        </div>
      </div>

      <div className="rounded-lg border border-[#E6E9F0] bg-white">
        <div className="border-b border-[#E6E9F0] px-5 py-4">
          <h2 className="text-base font-semibold text-[#0E1726]">Run History</h2>
        </div>
        <div className="divide-y divide-[#E6E9F0]">
          {data.runs.length === 0 && <p className="p-5 text-sm text-[#6B7488]">No red-team runs yet.</p>}
          {data.runs.map((item) => (
            <div key={item.workflow_id} className="flex flex-wrap items-center justify-between gap-3 px-5 py-4">
              <div>
                <p className="font-mono text-sm text-[#475069]">{item.workflow_id}</p>
                <p className="mt-1 text-xs text-[#6B7488]">{item.completed_at ? new Date(item.completed_at).toLocaleString() : "Incomplete"}</p>
              </div>
              <div className="flex items-center gap-3">
                {item.posture === "go" ? <CheckCircle2 className="h-4 w-4 text-emerald-700" /> : <XCircle className="h-4 w-4 text-red-700" />}
                <span className={`rounded-md border px-2.5 py-1 text-xs font-semibold ${badgeClass(item.posture)}`}>
                  {item.posture.replace("_", "-").toUpperCase()}
                </span>
                <span className="rounded-md border border-indigo-600/20 bg-indigo-50 px-2.5 py-1 text-xs font-semibold text-indigo-700">
                  {item.simulation_only === false ? "LIVE" : "SIMULATION"}
                </span>
                <span className="text-sm text-[#6B7488]">{item.failed} failed</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
