import type { Metadata } from "next";
import { MarketingPage } from "@/marketing/marketing-page";
import { securityContent } from "@/marketing/content";
import { createMarketingMetadata } from "@/marketing/seo";

export const metadata: Metadata = createMarketingMetadata({
  title: "Security & Trust — AuthClaw",
  description:
    "AuthClaw includes technical controls that support GDPR obligations and SOC 2 readiness, including tenant isolation, envelope encryption, and tamper-evident audit records.",
  path: "/security",
});

export default function SecurityPage() {
  return <MarketingPage content={securityContent} />;
}

