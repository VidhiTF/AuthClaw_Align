import type { ReactNode } from "react";
import { MarketingFooter } from "@/marketing/footer";
import { MarketingHeader } from "@/marketing/header";
import { RevealEffects } from "@/marketing/reveal-effects";
import "./marketing.css";

export default function MarketingLayout({ children }: { children: ReactNode }) {
  return (
    <div className="marketing-site">
      <MarketingHeader />
      {children}
      <MarketingFooter />
      <RevealEffects />
    </div>
  );
}

