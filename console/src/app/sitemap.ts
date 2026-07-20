import type { MetadataRoute } from "next";
import { marketingRoutes, marketingSiteUrl } from "@/marketing/config";

export default function sitemap(): MetadataRoute.Sitemap {
  return [
    marketingRoutes.home,
    marketingRoutes.product,
    marketingRoutes.pricing,
    marketingRoutes.security,
    marketingRoutes.company,
    marketingRoutes.privacy,
    marketingRoutes.terms,
    marketingRoutes.cookies,
    marketingRoutes.subprocessors,
    marketingRoutes.dpa,
  ].map((path) => ({
    url: new URL(path, marketingSiteUrl).toString(),
    changeFrequency: "monthly",
    priority: path === marketingRoutes.home ? 1 : 0.8,
  }));
}

