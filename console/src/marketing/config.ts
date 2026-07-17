export const marketingRoutes = {
  home: "/",
  product: "/product",
  pricing: "/pricing",
  security: "/security",
  company: "/company",
  login: "/login",
  trial: "/signup",
  demo: "/signup",
  contact: "/signup",
  careers: "/signup",
  trustReport: "/signup",
} as const;

export const marketingNavigation = [
  { href: marketingRoutes.product, label: "Product" },
  { href: marketingRoutes.pricing, label: "Pricing" },
  { href: marketingRoutes.security, label: "Security" },
  { href: marketingRoutes.company, label: "Company" },
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
] as const;

export const marketingSiteUrl = new URL(
  process.env.NEXT_PUBLIC_SITE_URL || "https://authclaw.ai"
);

