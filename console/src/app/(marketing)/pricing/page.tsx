import type { Metadata } from "next";
import { MarketingPage } from "@/marketing/marketing-page";
import { pricingContent } from "@/marketing/content";
import { PricingInteractions } from "@/marketing/pricing-interactions";
import { createMarketingMetadata } from "@/marketing/seo";

export const metadata: Metadata = createMarketingMetadata({
  title: "Pricing — AuthClaw",
  description:
    "AuthClaw pricing. Transparent plans that scale with protected AI traffic and supported frameworks, without a per-token markup.",
  path: "/pricing",
});

export default function PricingPage() {
  return (
    <MarketingPage content={pricingContent}>
      <PricingInteractions />
    </MarketingPage>
  );
}

