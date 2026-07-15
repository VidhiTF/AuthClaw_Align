import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  outputFileTracingRoot: __dirname,
  outputFileTracingExcludes: {
    "/*": ["next.config.ts"],
  },
  turbopack: {
    root: __dirname,
  },
  async rewrites() {
    return [
      {
        source: "/trust/shared/:path*",
        destination: "/trust-center/:path*",
      },
    ];
  },
};

export default nextConfig;
