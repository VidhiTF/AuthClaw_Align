import { CalendarClock, CheckCircle2, Clock3, ShieldCheck } from "lucide-react";
import { TrustSummary as TrustSummaryData, calculationVersion, evidenceAssessmentLabel, trustSummarySections } from "@/lib/trust-summary";

const sectionStyle = {
  verified: {
    icon: CheckCircle2,
    lightBadge: "border-emerald-500/25 bg-emerald-500/10 text-emerald-700",
    darkBadge: "border-emerald-500/25 bg-emerald-500/10 text-emerald-200",
  },
  in_progress: {
    icon: Clock3,
    lightBadge: "border-amber-500/25 bg-amber-500/10 text-amber-700",
    darkBadge: "border-amber-500/25 bg-amber-500/10 text-amber-100",
  },
  planned: {
    icon: CalendarClock,
    lightBadge: "border-slate-500/25 bg-slate-500/10 text-slate-600",
    darkBadge: "border-slate-500/25 bg-slate-500/10 text-slate-300",
  },
};

export function TrustSummary({ summary, dark = false }: { summary?: TrustSummaryData; dark?: boolean }) {
  const panel = dark ? "border-slate-800 bg-[#09090d]" : "border-[#E6E9F0] bg-white";
  const muted = dark ? "text-slate-400" : "text-[#6B7488]";
  const foreground = dark ? "text-white" : "text-[#0E1726]";
  const item = dark ? "border-slate-800 bg-[#07070a]" : "border-[#E6E9F0] bg-[#F5F7FA]";

  if (!summary) {
    return (
      <section className={`rounded-[20px] border p-5 shadow-xl ${panel}`} aria-labelledby="trust-summary-heading">
        <h2 id="trust-summary-heading" className={`flex items-center gap-2 text-sm font-bold ${foreground}`}>
          <ShieldCheck className="h-4 w-4 text-indigo-400" />
          Trust Summary
        </h2>
        <p className={`mt-2 text-xs ${muted}`}>Trust Summary is unavailable for this response.</p>
      </section>
    );
  }

  return (
    <section className={`rounded-[20px] border p-5 shadow-xl ${panel}`} aria-labelledby="trust-summary-heading">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 id="trust-summary-heading" className={`flex items-center gap-2 text-sm font-bold ${foreground}`}>
            <ShieldCheck className="h-4 w-4 text-indigo-400" />
            Trust Summary
          </h2>
          <p className={`mt-2 max-w-4xl text-xs leading-relaxed ${muted}`}>
            Verified means the control met AuthClaw&apos;s automated framework scoring criteria as of this assessment. Current criteria require qualified evidence; activity counts alone do not establish readiness. This summary is not an independent SOC 2 Type II report or a SOC 3 report, and no certification is implied.
          </p>
          <p className={`mt-2 max-w-4xl text-xs leading-relaxed ${muted}`}>Not qualified means required reviewed evidence or control conditions are unmet; it does not mean the feature is unimplemented.</p>
        </div>
        <div className={`text-[10px] ${muted}`}>
          <div>As of {new Date(summary.generated_at).toLocaleString()}</div>
          <div>Calculation version: {calculationVersion(summary.calculation_version)}</div>
          {calculationVersion(summary.calculation_version) === "legacy_unversioned" && <div>Legacy results do not establish current evidence qualification.</div>}
        </div>
      </div>

      <div className="mt-5 grid gap-4 lg:grid-cols-3">
        {trustSummarySections(summary).map((section) => {
          const style = sectionStyle[section.key];
          const Icon = style.icon;
          return (
            <div key={section.key} className={`rounded-xl border p-4 ${item}`}>
              <div className="flex items-center justify-between gap-2">
                <div className={`flex items-center gap-2 text-xs font-bold ${foreground}`}>
                  <Icon className="h-4 w-4" />
                  {section.label}
                </div>
                <span className={`rounded-full border px-2 py-0.5 text-[10px] font-bold ${dark ? style.darkBadge : style.lightBadge}`}>
                  {summary.counts[section.key]}
                </span>
              </div>
              <div className="mt-3 space-y-2">
                {section.controls.length === 0 ? (
                  <p className={`text-xs ${muted}`}>No controls in this category.</p>
                ) : (
                  section.controls.map((control) => (
                    <div key={`${control.framework}-${control.id}`} className={`rounded-lg border px-3 py-2 ${panel}`}>
                      <div className="flex items-center justify-between gap-2">
                        <span className={`truncate text-xs font-semibold ${foreground}`}>{control.name}</span>
                        <span className={`shrink-0 text-[10px] font-bold ${muted}`}>{control.score}%</span>
                      </div>
                      <div className={`mt-1 font-mono text-[10px] ${muted}`}>{control.framework} · {control.id}</div>
                      <div className={`mt-1 text-[10px] ${muted}`}>{evidenceAssessmentLabel(control.evidence_assessment)}</div>
                      {control.gaps?.map((gap) => <p key={gap} className={`mt-1 text-[10px] ${muted}`}>{gap}</p>)}
                    </div>
                  ))
                )}
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}
