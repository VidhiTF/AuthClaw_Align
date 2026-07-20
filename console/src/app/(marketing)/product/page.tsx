import type { Metadata } from "next";
import { MarketingPage } from "@/marketing/marketing-page";
import { productContent } from "@/marketing/content";
import { createMarketingMetadata } from "@/marketing/seo";

export const metadata: Metadata = createMarketingMetadata({
  title: "Product — AuthClaw",
  description:
    "The AuthClaw platform provides an in-line gateway, agentic remediation with human approval, and a continuous tamper-evident audit trail.",
  path: "/product",
});

export default function ProductPage() {
  return <MarketingPage content={productContent} />;
}

