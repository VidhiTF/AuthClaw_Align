"use client";

import { usePathname } from "next/navigation";
import { useEffect } from "react";

export function RevealEffects() {
  const pathname = usePathname();

  useEffect(() => {
    const items = document.querySelectorAll<HTMLElement>(".marketing-site .reveal");
    if (!("IntersectionObserver" in window)) {
      items.forEach((item) => item.classList.add("in"));
      return;
    }

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add("in");
            observer.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.14 }
    );
    items.forEach((item) => observer.observe(item));
    return () => observer.disconnect();
  }, [pathname]);

  return null;
}

