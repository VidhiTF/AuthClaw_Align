export const marketingRoutes = {
  home: "/",
  product: "/product",
  pricing: "/pricing",
  security: "/security",
  company: "/company",
  privacy: "/privacy",
  terms: "/terms",
  cookies: "/cookies",
  subprocessors: "/subprocessors",
  dpa: "/dpa",
  login: "/login",
  trial: "/early-access",
  demo: "/demo",
  earlyAccess: "/early-access",
  contact: "/early-access",
  careers: "/early-access",
  trustReport: "/early-access",
} as const;

export const marketingNavigation = [
  { href: marketingRoutes.product, label: "Product" },
  { href: marketingRoutes.pricing, label: "Pricing" },
  { href: marketingRoutes.security, label: "Security" },
  { href: marketingRoutes.company, label: "Company" },
  { href: marketingRoutes.earlyAccess, label: "Early Access" },
] as const;

export const marketingFooterGroups = [
  {
    heading: "Product",
    links: [
      { href: marketingRoutes.product, label: "In-line gateway" },
      { href: marketingRoutes.product, label: "Agentic remediation" },
      { href: marketingRoutes.product, label: "Audit & trust center" },
      { href: marketingRoutes.product, label: "Framework scoring" },
    ],
  },
  {
    heading: "Solutions",
    links: [
      { href: marketingRoutes.pricing, label: "Pricing" },
      { href: marketingRoutes.security, label: "Security" },
      { href: marketingRoutes.security, label: "Trust center" },
      { href: marketingRoutes.product, label: "Integrations" },
    ],
  },
  {
    heading: "Company",
    links: [
      { href: marketingRoutes.company, label: "About" },
      { href: marketingRoutes.careers, label: "Careers" },
      { href: marketingRoutes.contact, label: "Contact" },
      { href: marketingRoutes.security, label: "Responsible AI" },
    ],
  },
  {
    heading: "Legal",
    links: [
      { href: marketingRoutes.privacy, label: "Privacy Notice" },
      { href: marketingRoutes.terms, label: "Terms of Use" },
      { href: marketingRoutes.cookies, label: "Cookies" },
      { href: marketingRoutes.subprocessors, label: "Subprocessors" },
      { href: marketingRoutes.dpa, label: "DPA requests" },
    ],
  },
] as const;

export const marketingSiteUrl = new URL(
  process.env.NEXT_PUBLIC_SITE_URL || "https://authclaw.ai"
);

export const isMarketingSiteIndexable =
  process.env.NODE_ENV === "production" &&
  marketingSiteUrl.protocol === "https:" &&
  marketingSiteUrl.hostname === "authclaw.ai";

