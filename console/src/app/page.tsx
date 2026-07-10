"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

const navItems = [
  { label: "Platform", href: "#platform" },
  { label: "How it works", href: "#how" },
  { label: "Product", href: "#modules" },
  { label: "Frameworks", href: "#frameworks" },
  { label: "Why AuthClaw", href: "#why" },
];

const pillars = [
  {
    number: "01 / Gateway",
    title: "The checkpoint",
    body: "Gateway-routed prompts and responses pass through AuthClaw first. Sensitive data is detected and masked, hashed, or replaced before it leaves your environment.",
  },
  {
    number: "02 / Agent",
    title: "The remediation agent",
    body: "The agent scans connected systems, explains compliance gaps, prepares safe diffs, and waits for human approval before any high-risk action.",
  },
  {
    number: "03 / Audit",
    title: "The audit recorder",
    body: "Requests, decisions, approvals, and exports are written to tamper-evident audit records with verification support for reviewers.",
  },
];

const modules = [
  {
    eyebrow: "In-line gateway",
    title: "A safer path to every model.",
    body: "Route AI traffic through AuthClaw without changing public API contracts. Redaction and policy checks run before provider egress, including streaming-safe paths.",
    points: ["OpenAI-compatible, OpenAI, Anthropic, Azure OpenAI, and Cohere adapters", "Masking, salted hashing, and synthetic replacement strategies", "YAML and OPA-backed policy enforcement"],
    rows: [["support-bot prompt", "2 fields masked"], ["billing-agent prompt", "blocked"], ["claims response", "clean"], ["intake-form prompt", "1 field hashed"]],
  },
  {
    eyebrow: "Agentic remediation",
    title: "The agent proposes. A human decides.",
    body: "AuthClaw prepares remediation plans and approval envelopes. Destructive execution requires a fresh action-bound MFA approval and expires if untouched.",
    points: ["Scoped, short-lived worker tokens", "Approval queue with MFA confirmation", "Single-use, tenant-bound approval enforcement"],
    rows: [["Restrict bucket policy", "awaiting approval"], ["Rotate exposed API key", "approved"], ["Enable audit logging", "approved"], ["Delete public snapshot", "needs MFA"]],
  },
  {
    eyebrow: "Continuous audit and trust",
    title: "Proof that cannot be quietly changed.",
    body: "AuthClaw records sanitized audit events, builds verifiable export packages, and powers a shareable Trust Center without exposing raw provider payloads.",
    points: ["Hash-chain verification", "Signed audit export package support", "Access logs for report and trust artifacts"],
    rows: [["#4471 redaction", "hash ok"], ["#4472 approval", "hash ok"], ["#4473 execute", "hash ok"], ["#4474 export", "signed"]],
  },
  {
    eyebrow: "Framework scoring",
    title: "Readiness you can read at a glance.",
    body: "SOC 2, GDPR, and HIPAA readiness surfaces are driven by backend framework, control, evidence, and assessment records.",
    points: ["Framework scores and drill-downs", "Control-to-evidence mapping", "Reviewer language without certification overclaims"],
    rows: [["SOC 2", "evidence linked"], ["GDPR", "mapped controls"], ["HIPAA", "review ready"], ["Gaps", "owner visible"]],
  },
];

function AuthClawMark() {
  return (
    <span className="relative h-8 w-8 overflow-hidden rounded-lg bg-gradient-to-br from-violet-700 to-[#1B3663]">
      <span className="absolute inset-0 rotate-45 border-l-4 border-t-4 border-white/90" />
      <span className="absolute right-1 top-1 h-2 w-2 rounded-sm bg-[#E9A93C]" />
    </span>
  );
}

export default function PublicHomePage() {
  const [menuOpen, setMenuOpen] = useState(false);
  const [masked, setMasked] = useState(false);
  const [latency, setLatency] = useState("+38ms local");

  useEffect(() => {
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) return;
    const values = ["+38ms local", "+41ms local", "+36ms local", "+44ms local"];
    let index = 0;
    const timer = window.setInterval(() => {
      setMasked(true);
      setLatency(values[index % values.length]);
      index += 1;
      window.setTimeout(() => setMasked(false), 1200);
    }, 3200);
    return () => window.clearInterval(timer);
  }, []);

  const closeMenu = () => setMenuOpen(false);

  return (
    <main className="min-h-screen overflow-x-hidden bg-[#FBFAF9] text-[#0E1726]">
      <div className="bg-[#08152B] px-4 py-2 text-center font-mono text-xs tracking-wide text-[#D7E0F2]">
        <b className="text-white">AuthClaw</b> is the runtime gateway for AI compliance evidence
        <span className="mx-2 text-[#E9A93C]">/</span> SOC 2 <span className="mx-2 text-[#E9A93C]">/</span> HIPAA <span className="mx-2 text-[#E9A93C]">/</span> GDPR
      </div>

      <header className="sticky top-0 z-50 border-b border-[#E6E9F0] bg-[#FBFAF9]/90 backdrop-blur">
        <div className="mx-auto flex h-16 max-w-6xl items-center gap-7 px-5">
          <a href="#top" className="flex items-center gap-3 font-bold tracking-tight text-[#0E1726]" onClick={closeMenu}>
            <AuthClawMark />
            <span className="text-xl">AuthClaw<span className="text-violet-700">.ai</span></span>
          </a>
          <nav className="hidden gap-6 md:flex" aria-label="Public navigation">
            {navItems.map((item) => (
              <a key={item.href} href={item.href} className="text-sm font-medium text-[#475069] hover:text-[#0E1726]">
                {item.label}
              </a>
            ))}
          </nav>
          <div className="ml-auto hidden items-center gap-4 md:flex">
            <Link href="/login" className="text-sm font-medium text-[#475069] hover:text-[#0E1726]">Log in</Link>
            <a href="#demo" className="rounded-lg bg-violet-700 px-5 py-3 text-sm font-semibold text-white shadow-lg shadow-violet-900/20 hover:bg-violet-600">View walkthrough</a>
          </div>
          <button
            type="button"
            className="ml-auto rounded-lg border border-[#E6E9F0] px-3 py-2 text-sm font-semibold text-[#0E1726] md:hidden"
            aria-expanded={menuOpen}
            aria-controls="public-mobile-menu"
            onClick={() => setMenuOpen((value) => !value)}
          >
            Menu
          </button>
        </div>
        {menuOpen ? (
          <nav id="public-mobile-menu" className="border-t border-[#E6E9F0] bg-[#FBFAF9] px-5 py-4 md:hidden" aria-label="Mobile navigation">
            <div className="grid gap-3">
              {navItems.map((item) => (
                <a key={item.href} href={item.href} onClick={closeMenu} className="rounded-lg px-2 py-2 text-sm font-medium text-[#475069] hover:bg-violet-50 hover:text-violet-700">
                  {item.label}
                </a>
              ))}
              <Link href="/login" onClick={closeMenu} className="rounded-lg border border-[#E6E9F0] px-4 py-3 text-center text-sm font-semibold text-[#0E1726]">Log in</Link>
            </div>
          </nav>
        ) : null}
      </header>

      <section id="top" className="bg-[radial-gradient(circle_at_78%_0%,rgba(109,40,217,0.10),transparent_38%),radial-gradient(circle_at_6%_8%,rgba(233,169,60,0.10),transparent_32%)]">
        <div id="platform" className="mx-auto grid max-w-6xl gap-12 px-5 py-16 md:grid-cols-2 md:items-center md:py-20">
          <div>
            <p className="font-mono text-xs uppercase tracking-[0.18em] text-violet-700">The runtime layer for AI compliance</p>
            <h1 className="mt-5 text-4xl font-bold leading-tight tracking-tight text-[#0E1726] md:text-6xl">
              Stop sensitive data <span className="text-violet-700">before</span> it reaches the model.
            </h1>
            <p className="mt-6 max-w-xl text-lg text-[#475069]">
              AuthClaw sits in the live path between your applications and AI. It redacts sensitive data, enforces policy, supports approved remediation workflows, and keeps verifiable evidence for reviewers.
            </p>
            <div className="mt-8 flex flex-wrap gap-3">
              <a href="#demo" className="rounded-lg bg-violet-700 px-5 py-3 text-sm font-semibold text-white shadow-lg shadow-violet-900/20 hover:bg-violet-600">View walkthrough</a>
              <a href="#how" className="rounded-lg border border-[#E6E9F0] px-5 py-3 text-sm font-semibold text-[#0E1726] hover:border-violet-300 hover:text-violet-700">See how it works</a>
            </div>
            <div className="mt-9">
              <p className="font-mono text-xs uppercase tracking-[0.14em] text-[#6B7488]">Implemented framework surfaces</p>
              <div className="mt-3 flex flex-wrap gap-2">
                {["SOC 2", "HIPAA", "GDPR"].map((item) => (
                  <span key={item} className="rounded-full border border-[#E6E9F0] bg-white px-4 py-2 text-xs font-semibold text-[#12294B]">{item}</span>
                ))}
              </div>
            </div>
          </div>

          <div className="relative rounded-3xl border border-white/10 bg-gradient-to-b from-[#0B1F3F] to-[#08152B] p-5 text-[#E7EDF9] shadow-2xl shadow-[#08152B]/40" aria-label="Gateway redaction visual">
            <div className="absolute right-4 top-4 rounded-full border border-emerald-500/40 bg-emerald-700/20 px-3 py-1 font-mono text-xs text-emerald-200">{latency}</div>
            <div className="mb-4 flex items-center gap-2 pr-24 font-mono text-xs tracking-wide text-slate-400">
              <span className="h-3 w-3 rounded-full bg-slate-600" />
              <span className="h-3 w-3 rounded-full bg-slate-600" />
              <span className="h-3 w-3 rounded-full bg-[#E9A93C]" />
              authclaw / in-line gateway
            </div>
            <div className="grid gap-3">
              <div className="rounded-xl border border-white/10 bg-white/5 p-4">
                <div className="mb-2 flex justify-between font-mono text-[11px] uppercase tracking-[0.14em] text-slate-400"><span>Inbound prompt</span><span>app to authclaw</span></div>
                <p className="font-mono text-sm leading-7 text-slate-200">
                  summarize chart for patient <span className="rounded bg-amber-500/20 px-1 text-amber-200">{masked ? "******" : "Priya Nair"}</span>, dob <span className="rounded bg-amber-500/20 px-1 text-amber-200">{masked ? "******" : "04/12/1986"}</span>, mrn <span className="rounded bg-amber-500/20 px-1 text-amber-200">{masked ? "******" : "8830-221"}</span>
                </p>
              </div>
              <div className="mx-auto text-slate-500">v</div>
              <div className="rounded-xl border border-violet-400/40 bg-violet-700/10 p-4">
                <div className="mb-3 flex justify-between font-mono text-[11px] uppercase tracking-[0.14em] text-violet-200"><span>AuthClaw</span><span>redact / enforce / log</span></div>
                <div className="flex flex-wrap gap-2">
                  {["Presidio + NER", "policy checked", "audit chained"].map((item) => (
                    <span key={item} className="rounded-md border border-white/10 bg-white/10 px-3 py-1 font-mono text-xs text-slate-200">{item}</span>
                  ))}
                </div>
              </div>
              <div className="mx-auto text-slate-500">v</div>
              <div className="rounded-xl border border-white/10 bg-white/5 p-4">
                <div className="mb-2 flex justify-between font-mono text-[11px] uppercase tracking-[0.14em] text-slate-400"><span>Forwarded to model</span><span>authclaw to provider</span></div>
                <p className="font-mono text-sm leading-7 text-slate-200">summarize chart for patient <span className="rounded bg-violet-500/25 px-1 text-violet-200">[NAME]</span>, dob <span className="rounded bg-violet-500/25 px-1 text-violet-200">[DATE]</span>, mrn <span className="rounded bg-violet-500/25 px-1 text-violet-200">[ID]</span></p>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="bg-[#0B1F3F] py-16 text-white">
        <div className="mx-auto grid max-w-6xl gap-10 px-5 md:grid-cols-2 md:items-center">
          <div>
            <p className="font-mono text-xs uppercase tracking-[0.18em] text-violet-300">Evidence first, overclaims avoided</p>
            <h2 className="mt-4 text-3xl font-bold leading-tight md:text-4xl">Most tools describe risk later. AuthClaw enforces policy in the request path.</h2>
            <p className="mt-5 text-lg text-slate-300">Local benchmarks, verifiable audit exports, OPA mode, and staging runbooks are built in. Production claims still require staging, HA, pentest, and auditor evidence.</p>
          </div>
          <div className="grid overflow-hidden rounded-2xl border border-white/10 sm:grid-cols-2">
            {[["<=50ms", "local benchmark target, staging proof pending"], ["99.99%", "uptime objective, HA drill pending"], ["Gateway", "routed traffic inspection"], ["Export", "cryptographic verification support"]].map(([top, bottom]) => (
              <div key={top} className="border border-white/10 bg-[#08152B] p-6">
                <div className="text-3xl font-bold text-white">{top}</div>
                <div className="mt-2 text-sm text-slate-400">{bottom}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="mx-auto max-w-6xl px-5 py-20">
        <p className="font-mono text-xs uppercase tracking-[0.18em] text-violet-700">One gateway, three jobs</p>
        <h2 className="mt-4 max-w-3xl text-3xl font-bold tracking-tight md:text-5xl">Everything AI touches, governed in one place.</h2>
        <div className="mt-10 grid gap-5 md:grid-cols-3">
          {pillars.map((pillar) => (
            <article key={pillar.number} className="rounded-3xl border border-[#E6E9F0] bg-white p-7 shadow-sm">
              <div className="mb-5 h-1 w-20 rounded-full bg-gradient-to-r from-violet-700 to-[#E9A93C]" />
              <p className="font-mono text-xs uppercase tracking-wide text-[#6B7488]">{pillar.number}</p>
              <h3 className="mt-4 text-xl font-semibold">{pillar.title}</h3>
              <p className="mt-3 text-sm leading-6 text-[#475069]">{pillar.body}</p>
            </article>
          ))}
        </div>
      </section>

      <section id="how" className="border-y border-[#E6E9F0] bg-[#F5F7FA] py-16">
        <div className="mx-auto max-w-6xl px-5">
          <p className="font-mono text-xs uppercase tracking-[0.18em] text-violet-700">The request lifecycle</p>
          <h2 className="mt-4 text-3xl font-bold md:text-4xl">Four steps, on every gateway-routed call.</h2>
          <div className="mt-10 grid gap-5 md:grid-cols-4">
            {["Intercept native request", "Redact and enforce policy", "Forward clean payload", "Record verifiable audit"].map((step, index) => (
              <div key={step} className="rounded-2xl bg-white p-6 shadow-sm">
                <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-[#12294B] text-sm font-bold text-white">{index + 1}</div>
                <h3 className="mt-5 text-lg font-semibold">{step}</h3>
                <p className="mt-2 text-sm text-[#475069]">Built for deterministic evidence and safe failure behavior.</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section id="modules" className="mx-auto max-w-6xl px-5 py-20">
        <div className="text-center">
          <p className="font-mono text-xs uppercase tracking-[0.18em] text-violet-700">The platform</p>
          <h2 className="mt-4 text-3xl font-bold md:text-5xl">Four products. One in-line service.</h2>
        </div>
        <div className="mt-10 grid gap-8">
          {modules.map((module, index) => (
            <article key={module.title} className="grid gap-7 rounded-3xl border border-[#E6E9F0] bg-white p-6 shadow-sm md:grid-cols-2 md:items-center">
              <div className={index % 2 ? "md:order-2" : ""}>
                <p className="font-mono text-xs uppercase tracking-[0.18em] text-[#C9862A]">{module.eyebrow}</p>
                <h3 className="mt-3 text-2xl font-semibold md:text-3xl">{module.title}</h3>
                <p className="mt-4 text-[#475069]">{module.body}</p>
                <ul className="mt-5 grid gap-3 text-sm text-[#0E1726]">
                  {module.points.map((point) => <li key={point}>- {point}</li>)}
                </ul>
              </div>
              <div className="rounded-2xl border border-[#E6E9F0] bg-[#FBFAF9] p-5">
                <div className="mb-3 flex items-center justify-between border-b border-[#EEF1F6] pb-3 font-mono text-xs text-[#6B7488]">
                  <span>{module.eyebrow.toLowerCase()}</span><span>live</span>
                </div>
                {module.rows.map(([name, status]) => (
                  <div key={name} className="flex items-center justify-between border-b border-dashed border-[#EEF1F6] py-3 text-sm last:border-0">
                    <span>{name}</span>
                    <span className="rounded-full bg-violet-50 px-3 py-1 font-mono text-xs text-violet-700">{status}</span>
                  </div>
                ))}
              </div>
            </article>
          ))}
        </div>
      </section>

      <section id="frameworks" className="border-y border-[#E6E9F0] bg-[#F5F7FA] py-16">
        <div className="mx-auto grid max-w-6xl gap-10 px-5 md:grid-cols-2">
          <div>
            <h3 className="font-semibold">Provider adapters with contract coverage</h3>
            <div className="mt-4 flex flex-wrap gap-2">
              {["OpenAI", "Anthropic", "Azure OpenAI", "Cohere", "Groq/OpenAI-compatible"].map((item) => <span key={item} className="rounded-lg border border-[#E6E9F0] bg-white px-4 py-2 text-sm font-semibold">{item}</span>)}
            </div>
          </div>
          <div>
            <h3 className="font-semibold">Framework surfaces implemented</h3>
            <div className="mt-4 flex flex-wrap gap-2">
              {["SOC 2", "HIPAA", "GDPR"].map((item) => <span key={item} className="rounded-lg border border-[#E6E9F0] bg-white px-4 py-2 text-sm font-semibold">{item}</span>)}
              <span className="rounded-lg border border-[#E6E9F0] bg-white px-4 py-2 text-sm text-[#6B7488]">Additional frameworks: roadmap-ready</span>
            </div>
          </div>
        </div>
      </section>

      <section id="why" className="mx-auto max-w-6xl px-5 py-20">
        <p className="font-mono text-xs uppercase tracking-[0.18em] text-violet-700">Why AuthClaw</p>
        <h2 className="mt-4 max-w-3xl text-3xl font-bold md:text-5xl">Other tools describe risk. AuthClaw helps remove it in the path.</h2>
        <div className="mt-10 overflow-hidden rounded-3xl border border-[#E6E9F0] bg-white shadow-sm">
          {[["Sensitive data", "Reviewed after the fact", "Redacted before provider egress"], ["Compliance gaps", "Flagged in a report", "Linked to governed remediation"], ["Audit evidence", "Assembled by hand", "Recorded and exportable"], ["Human role", "Doing every manual step", "Approving risky decisions"]].map(([label, oldWay, authclaw]) => (
            <div key={label} className="grid gap-2 border-b border-[#EEF1F6] p-5 text-sm last:border-0 md:grid-cols-3">
              <b>{label}</b><span className="text-[#6B7488]">{oldWay}</span><span className="font-medium text-violet-700">{authclaw}</span>
            </div>
          ))}
        </div>
      </section>

      <section id="demo" className="bg-gradient-to-b from-[#0B1F3F] to-[#08152B] px-5 py-20 text-center text-white">
        <p className="font-mono text-xs uppercase tracking-[0.18em] text-[#E9A93C]">Get started</p>
        <h2 className="mt-4 text-3xl font-bold md:text-5xl">Put AuthClaw in front of your models.</h2>
        <p className="mx-auto mt-5 max-w-2xl text-lg text-slate-300">Open the console to review gateway routing, redaction, approvals, audit verification, and evidence workflows against your configured tenant.</p>
        <div className="mt-8 flex flex-wrap justify-center gap-3">
          <Link href="/login" className="rounded-lg bg-[#E9A93C] px-5 py-3 text-sm font-semibold text-[#2A1B04] hover:bg-[#f2b653]">Log in to console</Link>
          <a href="#platform" className="rounded-lg border border-white/20 px-5 py-3 text-sm font-semibold text-white hover:bg-white/10">Back to top</a>
        </div>
      </section>

      <footer className="bg-[#08152B] px-5 py-12 text-sm text-slate-300">
        <div className="mx-auto grid max-w-6xl gap-8 md:grid-cols-[1.5fr_1fr_1fr_1fr]">
          <div>
            <div className="flex items-center gap-3 font-bold text-white"><AuthClawMark />AuthClaw<span className="text-violet-300">.ai</span></div>
            <p className="mt-4 max-w-sm text-slate-400">The runtime layer for AI compliance. Redact, remediate with approval, and prove it with a tamper-evident trail.</p>
          </div>
          <div><h3 className="font-semibold uppercase tracking-wide text-slate-500">Platform</h3><ul className="mt-3 grid gap-2"><li><a href="#modules">Gateway</a></li><li><a href="#modules">Remediation</a></li><li><a href="#modules">Audit</a></li></ul></div>
          <div><h3 className="font-semibold uppercase tracking-wide text-slate-500">Frameworks</h3><ul className="mt-3 grid gap-2"><li>SOC 2</li><li>HIPAA</li><li>GDPR</li></ul></div>
          <div><h3 className="font-semibold uppercase tracking-wide text-slate-500">Access</h3><ul className="mt-3 grid gap-2"><li><Link href="/login">Log in</Link></li><li><a href="#demo">Walkthrough</a></li><li><Link href="/trust/shared/demo">Shared trust page example</Link></li></ul></div>
        </div>
        <div className="mx-auto mt-10 flex max-w-6xl flex-wrap justify-between gap-3 border-t border-white/10 pt-5 text-xs text-slate-500">
          <span>© 2026 AuthClaw. All rights reserved.</span>
          <span>Evidence-supported posture. External audit and production deployment proof are separate gates.</span>
        </div>
      </footer>
    </main>
  );
}
