import type { ReactNode } from "react";
import { marketingRoutes } from "./config";

const ctaDestinations = {
  trial: marketingRoutes.trial,
  demo: marketingRoutes.demo,
  contact: marketingRoutes.contact,
  careers: marketingRoutes.careers,
  trustReport: marketingRoutes.trustReport,
} as const;

function resolveCtaDestinations(content: string) {
  return Object.entries(ctaDestinations).reduce(
    (html, [name, destination]) =>
      html.replaceAll(`{{${name}}}`, destination),
    content
  );
}

export function MarketingPage({
  content,
  children,
}: {
  content: string;
  children?: ReactNode;
}) {
  return (
    <main>
      <div
        dangerouslySetInnerHTML={{
          __html: resolveCtaDestinations(content),
        }}
      />
      {children}
    </main>
  );
}

