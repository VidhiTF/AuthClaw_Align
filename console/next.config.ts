import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  outputFileTracingRoot: __dirname,
  outputFileTracingExcludes: {
    "/*": ["next.config.ts"],
  },
  turbopack: {
    root: __dirname,
  },
};

export default nextConfig;
