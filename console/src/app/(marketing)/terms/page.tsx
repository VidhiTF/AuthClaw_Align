import type { Metadata } from "next";
import Link from "next/link";
import { LegalNotice } from "@/marketing/legal-notice";
import { TERMS_VERSION } from "@/marketing/legal-config";
import { createMarketingMetadata } from "@/marketing/seo";

export const metadata: Metadata = createMarketingMetadata({
  title: "Terms of Use — AuthClaw",
  description: "Controlled-beta terms governing authorized use of AuthClaw.",
  path: "/terms",
});

export default function TermsPage() {
  return (
    <LegalNotice
      title="Terms of Use"
      version={TERMS_VERSION}
      summary="These terms govern authorized access to the AuthClaw controlled beta and supplement any signed customer agreement."
    >
      <section>
        <h2>Controlled-beta service</h2>
        <p>
          AuthClaw is an evolving beta service. Features, limits, integrations,
          availability, and data-handling options may change. A signed order form,
          DPA, BAA, SLA, or other negotiated agreement controls if it conflicts with
          these website terms.
        </p>
      </section>

      <section>
        <h2>Authorized use</h2>
        <p>
          Users must provide accurate account information, protect credentials,
          follow tenant access rules, and use the service only for lawful,
          authorized purposes. Customers are responsible for their users, source
          data, configured providers, policies, retention settings, and legal basis
          for processing.
        </p>
      </section>

      <section>
        <h2>Prohibited use</h2>
        <ul>
          <li>Do not attempt unauthorized access or bypass tenant boundaries.</li>
          <li>Do not introduce malware or interfere with service availability.</li>
          <li>Do not submit data or connect systems without authority to do so.</li>
          <li>
            Do not use readiness scores or product output as legal advice,
            certification, or an independent auditor opinion.
          </li>
        </ul>
      </section>

      <section>
        <h2>Security and customer responsibility</h2>
        <p>
          AuthClaw provides configurable technical controls, but customers remain
          responsible for access reviews, provider agreements, lawful processing,
          incident response, backups, training, and compliance decisions. Suspected
          vulnerabilities should be reported through the{" "}
          <Link href="/security#security-contact">security contact</Link>.
        </p>
      </section>

      <section>
        <h2>Third-party services</h2>
        <p>
          Customer-selected cloud, identity, email, and model providers are governed
          by their own terms. AuthClaw does not control their services and does not
          guarantee their availability or output.
        </p>
      </section>

      <section>
        <h2>Beta warranty and availability</h2>
        <p>
          Except where a signed agreement says otherwise, the beta is provided on an
          as-available basis without a public uptime SLA or guarantee that every
          sensitive value, threat, or compliance gap will be detected. Contractual
          remedies and liability terms belong in the applicable signed agreement.
        </p>
      </section>

      <section>
        <h2>Changes</h2>
        <p>
          Material updates receive a new version and effective date. Where renewed
          acceptance is required, AuthClaw will request it before continued use.
        </p>
      </section>
    </LegalNotice>
  );
}
