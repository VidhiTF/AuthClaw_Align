"use client";

import { useEffect } from "react";

export function GatewayDemo() {
  useEffect(() => {
    const latency = document.getElementById("lat");
    const pii = document.querySelectorAll<HTMLElement>("#inNode .pii");
    if (!latency || !pii.length) return;

    const values = ["+32ms", "+38ms", "+41ms", "+36ms"];
    let index = 0;
    let restoreTimer: number | undefined;
    const interval = window.setInterval(() => {
      index = (index + 1) % values.length;
      latency.textContent = values[index];
      pii.forEach((item) => {
        item.classList.add("masked");
        item.textContent = "------";
      });
      restoreTimer = window.setTimeout(() => {
        pii.forEach((item) => {
          item.classList.remove("masked");
          item.textContent = item.dataset.real || "";
        });
      }, 700);
    }, 2600);

    return () => {
      window.clearInterval(interval);
      if (restoreTimer) window.clearTimeout(restoreTimer);
    };
  }, []);

  return null;
}
