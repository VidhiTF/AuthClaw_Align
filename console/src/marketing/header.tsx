"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { marketingNavigation, marketingRoutes } from "./config";

export function MarketingHeader() {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);
  const buttonRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    function closeOnEscape(event: KeyboardEvent) {
      if (event.key === "Escape" && open) {
        setOpen(false);
        buttonRef.current?.focus();
      }
    }
    document.addEventListener("keydown", closeOnEscape);
    return () => document.removeEventListener("keydown", closeOnEscape);
  }, [open]);

  return (
    <header className="nav">
      <div className="wrap nav-in">
        <Link className="brand" href={marketingRoutes.home} aria-label="AuthClaw home">
          <span className="mark" aria-hidden="true" />
          AuthClaw<span className="ai">.ai</span>
        </Link>
        <nav className="links" aria-label="Primary navigation">
          {marketingNavigation.map((item) => (
            <Link
              className={pathname === item.href ? "active" : undefined}
              href={item.href}
              aria-current={pathname === item.href ? "page" : undefined}
              key={item.href}
            >
              {item.label}
            </Link>
          ))}
        </nav>
        <div className="nav-cta">
          <Link className="login" href={marketingRoutes.login}>
            Log in
          </Link>
          <Link className="btn btn-primary" href={marketingRoutes.demo}>
            Book a demo
          </Link>
          <button
            ref={buttonRef}
            className="burger"
            type="button"
            aria-label={open ? "Close menu" : "Open menu"}
            aria-controls="marketing-mobile-menu"
            aria-expanded={open}
            onClick={() => setOpen((current) => !current)}
          >
            <span aria-hidden="true" />
          </button>
        </div>
      </div>
      <nav
        className={`mobilemenu${open ? " open" : ""}`}
        id="marketing-mobile-menu"
        aria-label="Mobile navigation"
        hidden={!open}
      >
        {marketingNavigation.map((item) => (
          <Link
            className={pathname === item.href ? "active" : undefined}
            href={item.href}
            aria-current={pathname === item.href ? "page" : undefined}
            key={item.href}
            onClick={() => setOpen(false)}
          >
            {item.label}
          </Link>
        ))}
        <div className="mm-cta">
          <Link className="btn btn-ghost" href={marketingRoutes.login}>
            Log in
          </Link>
          <Link className="btn btn-primary" href={marketingRoutes.demo}>
            Book a demo
          </Link>
        </div>
      </nav>
    </header>
  );
}
