import type { Metadata } from "next";
import { LegalNotice } from "@/marketing/legal-notice";
import {
  legalContacts,
  PRIVACY_NOTICE_VERSION,
} from "@/marketing/legal-config";
import { createMarketingMetadata } from "@/marketing/seo";

export const metadata: Metadata = createMarketingMetadata({
  title: "DPA Requests — AuthClaw",
  description: "How customers request an AuthClaw Data Processing Addendum.",
  path: "/dpa",
});

export default function DpaPage() {
  return (
    <LegalNotice
      title="Data Processing Addendum Requests"
      version={PRIVACY_NOTICE_VERSION}
      summary="A DPA is provided through an authorized contractual review, not as evidence of certification or legal compliance."
    >
      <section>
        <h2>Request path</h2>
        <p>
          Email <a href={`mailto:${legalContacts.dpa}`}>{legalContacts.dpa}</a>{" "}
          with the customer organization, deployment model, primary operating
          regions, requested model providers, and contracting contact. Do not send
          production credentials or personal data in the request.
        </p>
      </section>

      <section>
        <h2>Review scope</h2>
        <p>
          The review identifies processing roles, instructions, security measures,
          subprocessor terms, international-transfer mechanism where applicable,
          incident notification, deletion or return, and audit cooperation. The
          final terms depend on the deployment and signed commercial agreement.
        </p>
      </section>

      <section>
        <h2>No automatic legal conclusion</h2>
        <p>
          Availability of a DPA request process does not mean every deployment is
          automatically legally compliant with GDPR. Each organization must assess its own
          processing, lawful basis, configuration, vendors, and obligations.
        </p>
      </section>
    </LegalNotice>
  );
}
