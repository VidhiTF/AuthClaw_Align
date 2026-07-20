"use client";

import { useEffect } from "react";

export function PricingInteractions() {
  useEffect(() => {
    const billingToggle = document.getElementById("billToggle");
    const monthlyButton = document.getElementById("billMonthly");
    const annualButton = document.getElementById("billAnnual");

    function setBilling(period: "m" | "a") {
      const annual = period === "a";
      billingToggle?.classList.toggle("annual", annual);
      monthlyButton?.classList.toggle("on", !annual);
      annualButton?.classList.toggle("on", annual);
      monthlyButton?.setAttribute("aria-pressed", String(!annual));
      annualButton?.setAttribute("aria-pressed", String(annual));
      document.querySelectorAll<HTMLElement>("[data-m][data-a]").forEach((item) => {
        item.textContent = item.dataset[period] || "";
      });
    }

    const showMonthly = () => setBilling("m");
    const showAnnual = () => setBilling("a");
    monthlyButton?.addEventListener("click", showMonthly);
    annualButton?.addEventListener("click", showAnnual);
    setBilling("a");

    const faqButtons = Array.from(
      document.querySelectorAll<HTMLButtonElement>(".qa > button")
    );
    faqButtons.forEach((button) => {
      const panelId = button.getAttribute("aria-controls");
      if (panelId) {
        document.getElementById(panelId)?.setAttribute("aria-hidden", "true");
      }
    });
    const toggleFaq = (button: HTMLButtonElement) => {
      const item = button.closest(".qa");
      const expanded = button.getAttribute("aria-expanded") === "true";
      item?.classList.toggle("open", !expanded);
      button.setAttribute("aria-expanded", String(!expanded));
      const panelId = button.getAttribute("aria-controls");
      if (panelId) {
        document
          .getElementById(panelId)
          ?.setAttribute("aria-hidden", String(expanded));
      }
    };
    const listeners = faqButtons.map((button) => {
      const listener = () => toggleFaq(button);
      button.addEventListener("click", listener);
      return { button, listener };
    });
    const closeFaqs = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      faqButtons.forEach((button) => {
        button.closest(".qa")?.classList.remove("open");
        button.setAttribute("aria-expanded", "false");
        const panelId = button.getAttribute("aria-controls");
        if (panelId) {
          document.getElementById(panelId)?.setAttribute("aria-hidden", "true");
        }
      });
    };
    document.addEventListener("keydown", closeFaqs);

    return () => {
      monthlyButton?.removeEventListener("click", showMonthly);
      annualButton?.removeEventListener("click", showAnnual);
      listeners.forEach(({ button, listener }) =>
        button.removeEventListener("click", listener)
      );
      document.removeEventListener("keydown", closeFaqs);
    };
  }, []);

  return null;
}
