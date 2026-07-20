export type TrustSummaryControl = {
  framework: string;
  id: string;
  name: string;
  score: number;
  status: "compliant" | "partial" | "non_compliant";
};

export type TrustSummary = {
  generated_at: string;
  counts: {
    verified: number;
    in_progress: number;
    planned: number;
  };
  verified: TrustSummaryControl[];
  in_progress: TrustSummaryControl[];
  planned: TrustSummaryControl[];
};

export const trustSummarySections = (summary?: TrustSummary) => [
  { key: "verified" as const, label: "Verified", controls: summary?.verified ?? [] },
  { key: "in_progress" as const, label: "In Progress", controls: summary?.in_progress ?? [] },
  { key: "planned" as const, label: "Planned", controls: summary?.planned ?? [] },
];
