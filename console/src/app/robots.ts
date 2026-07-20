import type { MetadataRoute } from "next";
import { marketingSiteUrl } from "@/marketing/config";

export default function robots(): MetadataRoute.Robots {
  return {
    rules: {
      userAgent: "*",
      allow: [
        "/",
        "/product",
        "/pricing",
        "/security",
        "/company",
        "/privacy",
        "/terms",
        "/cookies",
        "/subprocessors",
        "/dpa",
      ],
      disallow: [
        "/api/",
        "/agent",
        "/approvals",
        "/audit",
        "/aws",
        "/compliance",
        "/connect",
        "/evidence",
        "/findings",
        "/frameworks",
        "/gateway",
        "/notifications",
        "/overview",
        "/policies",
        "/risk",
        "/settings",
        "/trust-center/",
      ],
    },
    sitemap: new URL("/sitemap.xml", marketingSiteUrl).toString(),
  };
}
