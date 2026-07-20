import type { Metadata } from "next";
import Link from "next/link";
import { LegalNotice } from "@/marketing/legal-notice";
import { PRIVACY_NOTICE_VERSION } from "@/marketing/legal-config";
import { createMarketingMetadata } from "@/marketing/seo";

export const metadata: Metadata = createMarketingMetadata({
  title: "Subprocessors — AuthClaw",
  description: "Current controlled-beta subprocessor categories for AuthClaw.",
  path: "/subprocessors",
});

export default function SubprocessorsPage() {
  return (
    <LegalNotice
      title="Subprocessor List"
      version={PRIVACY_NOTICE_VERSION}
      summary="The subprocessors used for a customer depend on the selected deployment and configured integrations."
    >
      <section>
        <h2>Current categories</h2>
        <table className="legal-table">
          <thead>
            <tr>
              <th scope="col">Provider or category</th>
              <th scope="col">Purpose</th>
              <th scope="col">When used</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Amazon Web Services</td>
              <td>Cloud hosting, networking, storage, and managed key operations.</td>
              <td>AuthClaw-managed AWS deployments</td>
            </tr>
            <tr>
              <td>Customer-selected model provider</td>
              <td>Processes authorized model requests after configured gateway controls.</td>
              <td>Only when the customer configures that provider</td>
            </tr>
            <tr>
              <td>Customer-selected identity provider</td>
              <td>Enterprise authentication and tenant identity mapping.</td>
              <td>Only when OIDC SSO is configured</td>
            </tr>
            <tr>
              <td>Configured email-delivery provider</td>
              <td>Delivers account verification, invitations, and security messages.</td>
              <td>Deployment-specific</td>
            </tr>
          </tbody>
        </table>
      </section>

      <section>
        <h2>Customer-selected providers</h2>
        <p>
          A configured AI, cloud, or identity provider may independently act as a
          processor or controller under its agreement with the customer. AuthClaw
          records the configured route but cannot make that provider&apos;s legal
          commitments on its behalf.
        </p>
      </section>

      <section>
        <h2>Changes and requests</h2>
        <p>
          Material changes receive a new list version. Customers can request
          deployment-specific details and contractual notice terms through the{" "}
          <Link href="/dpa">DPA request path</Link>.
        </p>
      </section>
    </LegalNotice>
  );
}
