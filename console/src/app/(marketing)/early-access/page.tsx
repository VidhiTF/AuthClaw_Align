import type { Metadata } from "next";
import { IntakeForm } from "@/marketing/intake-form";
import { createMarketingMetadata } from "@/marketing/seo";

export const metadata: Metadata = createMarketingMetadata({
  title: "Early Access — AuthClaw",
  description: "Request controlled early access to AuthClaw.",
  path: "/early-access",
});

export default function EarlyAccessPage() {
  return (
    <main className="intake-page">
      <div className="wrap">
        <IntakeForm
          requestedAccess="EARLY_ACCESS"
          sourcePage="/early-access"
          title="Request early access"
          description="Tell us how your organization plans to use AuthClaw."
        />
      </div>
    </main>
  );
}
