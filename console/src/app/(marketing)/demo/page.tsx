import type { Metadata } from "next";
import { IntakeForm } from "@/marketing/intake-form";
import { createMarketingMetadata } from "@/marketing/seo";

export const metadata: Metadata = createMarketingMetadata({
  title: "Book a Demo — AuthClaw",
  description: "Request a demonstration of the AuthClaw AI governance platform.",
  path: "/demo",
});

export default function DemoPage() {
  return (
    <main className="intake-page">
      <div className="wrap">
        <IntakeForm
          requestedAccess="DEMO"
          sourcePage="/demo"
          title="Book an AuthClaw demo"
          description="Tell us about your AI governance requirements and deployment goals."
        />
      </div>
    </main>
  );
}
