import Link from "next/link";
import { marketingFooterGroups, marketingRoutes } from "./config";

export function MarketingFooter() {
  return (
    <footer className="ft">
      <div className="wrap">
        <div className="ft-grid">
          <div>
            <Link className="brand" href={marketingRoutes.home} aria-label="AuthClaw home">
              <span className="mark" aria-hidden="true" />
              AuthClaw<span className="ai">.ai</span>
            </Link>
            <p className="desc">
              The runtime layer for AI compliance. Redact in real time,
              remediate with human approval, and prove it with a tamper-evident
              trail.
            </p>
          </div>
          {marketingFooterGroups.map((group) => (
            <div key={group.heading}>
              <h2>{group.heading}</h2>
              <ul>
                {group.links.map((link) => (
                  <li key={`${group.heading}-${link.label}`}>
                    <Link href={link.href}>{link.label}</Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
        <div className="ft-base">
          <span>© {new Date().getFullYear()} AuthClaw. All rights reserved.</span>
          <span className="made">
            A product by <b>AgentsArchitects.ai</b>
          </span>
        </div>
      </div>
    </footer>
  );
}

