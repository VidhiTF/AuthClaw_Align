import type { Metadata } from "next";
import Link from "next/link";
import { LegalNotice } from "@/marketing/legal-notice";
import {
  legalContacts,
  PRIVACY_NOTICE_VERSION,
} from "@/marketing/legal-config";
import { createMarketingMetadata } from "@/marketing/seo";

export const metadata: Metadata = createMarketingMetadata({
  title: "Privacy Notice — AuthClaw",
  description:
    "How AuthClaw handles personal data submitted through controlled-beta signup, demo, account, gateway, and support workflows.",
  path: "/privacy",
});

export default function PrivacyPage() {
  return (
    <LegalNotice
      title="Privacy Notice"
      version={PRIVACY_NOTICE_VERSION}
      summary="This notice explains the personal data AuthClaw collects during its controlled beta, why it is used, and the choices available to individuals."
    >
      <section>
        <h2>Scope and roles</h2>
        <p>
          AuthClaw is provided by AgentsArchitects.ai. For account, demo,
          early-access, website, and support interactions, the provider determines
          why the submitted contact and service data is used. When a customer sends
          data through the AuthClaw gateway, that customer determines the purpose of
          processing and must configure the service consistently with its own legal
          obligations.
        </p>
      </section>

      <section>
        <h2>Data collected</h2>
        <ul>
          <li>
            Demo, trial, and early-access forms: work email address, organization
            or tenant name, requested service, and form-submission metadata.
          </li>
          <li>
            Accounts: email address, password verifier, role, tenant membership,
            authentication events, and security settings.
          </li>
          <li>
            Service usage: request identifiers, configured provider and model,
            policy decisions, timing, error category, and audit metadata.
          </li>
          <li>
            Customer content: prompts, responses, uploaded documents, or detected
            personal data only when an authorized customer uses the relevant
            product workflow.
          </li>
          <li>
            Support and security reports: contact details and the information a
            sender chooses to include.
          </li>
        </ul>
      </section>

      <section>
        <h2>Purposes and legal grounds</h2>
        <p>
          Data is used to provide and secure the beta service, verify accounts,
          respond to requested demos or support, enforce policies, investigate
          incidents, meet contractual obligations, and improve reliability.
          Optional marketing communications require the applicable consent or
          another lawful basis and must provide an unsubscribe mechanism.
        </p>
      </section>

      <section>
        <h2>Sharing and international processing</h2>
        <p>
          Data may be processed by the infrastructure, identity, email, support,
          and model providers needed for the selected deployment. Customer-selected
          model providers receive content only when the customer configures that
          route. See the current <Link href="/subprocessors">subprocessor list</Link>{" "}
          and <Link href="/dpa">DPA request path</Link>.
        </p>
      </section>

      <section>
        <h2>Retention and deletion</h2>
        <p>
          AuthClaw minimizes stored content and applies product-specific retention
          settings. Account, security, audit, contractual, and backup records may
          require different retention periods. Authorized deletion requests are
          subject to verified identity and documented legal, security, or
          contractual exceptions.
        </p>
      </section>

      <section>
        <h2>Individual rights and contact</h2>
        <p>
          Depending on location and context, individuals may request access,
          correction, deletion, restriction, portability, or objection. Contact{" "}
          <a href={`mailto:${legalContacts.privacy}`}>{legalContacts.privacy}</a>.
          AuthClaw will verify the requester and coordinate with the relevant
          customer where that customer controls the data.
        </p>
      </section>

      <section>
        <h2>Product controls are not legal advice</h2>
        <p>
          AuthClaw includes technical controls that support privacy and GDPR
          obligations. Product features do not by themselves establish an
          organization&apos;s legal compliance.
        </p>
      </section>
    </LegalNotice>
  );
}
