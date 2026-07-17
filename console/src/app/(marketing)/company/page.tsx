import type { Metadata } from "next";
import { MarketingPage } from "@/marketing/marketing-page";
import { companyContent } from "@/marketing/content";
import { createMarketingMetadata } from "@/marketing/seo";

export const metadata: Metadata = createMarketingMetadata({
  title: "Company — AuthClaw",
  description:
    "AuthClaw is building the runtime layer for AI compliance as a product of AgentsArchitects.ai.",
  path: "/company",
});

export default function CompanyPage() {
  return <MarketingPage content={companyContent} />;
}

