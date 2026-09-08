"use client";

import { useEffect, useState } from "react";

interface RuntimeConfig {
  api_url: string;
  gateway_url: string;
}

export function useRuntimeConfig() {
  const [config, setConfig] = useState<RuntimeConfig | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    fetch("/api/runtime-config", { cache: "no-store", signal: controller.signal })
      .then((response) => (response.ok ? response.json() : Promise.reject(new Error("runtime config unavailable"))))
      .then((value: RuntimeConfig) => setConfig(value))
      .catch((error: unknown) => {
        if (!(error instanceof DOMException && error.name === "AbortError")) {
          console.error("Failed to load public runtime configuration");
        }
      });
    return () => controller.abort();
  }, []);

  return config;
}
