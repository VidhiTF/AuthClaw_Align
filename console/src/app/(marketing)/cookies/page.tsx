import type { Metadata } from "next";
import { LegalNotice } from "@/marketing/legal-notice";
import { PRIVACY_NOTICE_VERSION } from "@/marketing/legal-config";
import { createMarketingMetadata } from "@/marketing/seo";

export const metadata: Metadata = createMarketingMetadata({
  title: "Cookie & Analytics Disclosure — AuthClaw",
  description: "Cookies and similar technologies used by the AuthClaw website and console.",
  path: "/cookies",
});

export default function CookiesPage() {
  return (
    <LegalNotice
      title="Cookie & Analytics Disclosure"
      version={PRIVACY_NOTICE_VERSION}
      summary="AuthClaw uses essential security cookies. Optional analytics must not be enabled without an updated disclosure and the consent required by applicable law."
    >
      <section>
        <h2>Essential cookies</h2>
        <table className="legal-table">
          <thead>
            <tr>
              <th scope="col">Cookie</th>
              <th scope="col">Purpose</th>
              <th scope="col">Typical lifetime</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>authclaw_session</code></td>
              <td>Authenticates the console session and applies tenant access controls.</td>
              <td>Up to 24 hours or logout</td>
            </tr>
            <tr>
              <td><code>authclaw_oidc_state</code></td>
              <td>Protects an in-progress OIDC sign-in from request forgery and replay.</td>
              <td>Up to 10 minutes</td>
            </tr>
          </tbody>
        </table>
      </section>

      <section>
        <h2>Analytics and advertising</h2>
        <p>
          The controlled-beta website does not enable non-essential analytics or
          advertising cookies by default. If optional analytics are introduced,
          this page must identify the provider, data, purpose, duration, and opt-out
          method before deployment, and a consent control must be shown where
          required.
        </p>
      </section>

      <section>
        <h2>Browser controls</h2>
        <p>
          Browsers can block or delete cookies. Blocking essential cookies prevents
          authenticated console access but does not prevent viewing public pages.
        </p>
      </section>
    </LegalNotice>
  );
}
