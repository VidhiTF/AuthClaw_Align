import type { Metadata } from "next";
import { GatewayDemo } from "@/marketing/gateway-demo";
import { MarketingPage } from "@/marketing/marketing-page";
import { homeContent } from "@/marketing/content";
import { createMarketingMetadata } from "@/marketing/seo";

export const metadata: Metadata = createMarketingMetadata({
  title: "AuthClaw — The runtime layer for AI compliance",
  description:
    "AuthClaw is the in-line gateway for AI compliance. Redact configured sensitive-data patterns in real time, remediate gaps with human approval, and generate tamper-evident audit records.",
  path: "/",
});

export default function HomePage() {
  return (
    <MarketingPage content={homeContent}>
      <GatewayDemo />
    </MarketingPage>
  );
}

