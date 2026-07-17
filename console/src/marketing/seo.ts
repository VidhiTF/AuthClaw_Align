import type { Metadata } from "next";
import { marketingSiteUrl } from "./config";

type MarketingMetadataInput = {
  title: string;
  description: string;
  path: string;
};

export function createMarketingMetadata({
  title,
  description,
  path,
}: MarketingMetadataInput): Metadata {
  return {
    title,
    description,
    alternates: { canonical: path },
    openGraph: {
      type: "website",
      siteName: "AuthClaw",
      title,
      description,
      url: new URL(path, marketingSiteUrl),
    },
    twitter: {
      card: "summary_large_image",
      title,
      description,
    },
  };
}
