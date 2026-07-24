import type { Metadata } from "next";
import { isMarketingSiteIndexable, marketingSiteUrl } from "./config";

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
    robots: isMarketingSiteIndexable
      ? undefined
      : { index: false, follow: false },
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
