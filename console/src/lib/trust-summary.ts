export type TrustSummaryControl = {
  framework: string;
  id: string;
  name: string;
  score: number;
  status: "compliant" | "partial" | "non_compliant";
  evidence_assessment?: EvidenceAssessment;
  gaps?: string[];
};

export type TrustSummary = {
  generated_at: string;
  calculation_version?: string;
  counts: {
    verified: number;
    in_progress: number;
    planned: number;
  };
  verified: TrustSummaryControl[];
  in_progress: TrustSummaryControl[];
  planned: TrustSummaryControl[];
};

export type EvidenceAssessment = {
  state: "qualified" | "blocked";
  reason_codes: string[];
  required_count: number;
  qualified_count: number;
  as_of: string;
  valid_until: string | null;
};

export type ActivityDiagnostics = {
  score: number;
  evidence: string[];
  gaps: string[];
  authoritative: false;
};

export const calculationVersion = (version?: string) => version?.trim() || "legacy_unversioned";

// Render the server's decision; activity counts never classify a control here.
export const evidenceAssessmentLabel = (assessment?: EvidenceAssessment) => assessment
  ? `Evidence ${assessment.state}: ${assessment.qualified_count}/${assessment.required_count} requirements qualified`
  : "Evidence qualification unavailable for this legacy response";

type HistoryIdentity = {
  id?: string;
  framework: string;
  snapshot_date: string;
  calculation_version?: string;
};

export function scoreHistoryEntries<T extends HistoryIdentity>(items: T[]) {
  const previousVersions = new Map<string, string>();
  return items.map((item) => {
    const version = calculationVersion(item.calculation_version);
    const previous = previousVersions.get(item.framework);
    previousVersions.set(item.framework, version);
    return {
      item, version,
      key: item.id || `${item.framework}-${item.snapshot_date}-${version}`,
      methodChanged: previous !== undefined && previous !== version,
    };
  });
}

export const trustSummarySections = (summary?: TrustSummary) => [
  { key: "verified" as const, label: "Verified", controls: summary?.verified ?? [] },
  { key: "in_progress" as const, label: "In Progress", controls: summary?.in_progress ?? [] },
  { key: "planned" as const, label: "Not qualified", controls: summary?.planned ?? [] },
];
