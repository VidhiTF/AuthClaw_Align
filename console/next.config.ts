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
  async redirects() {
    return [
      { source: "/index.html", destination: "/", permanent: true },
      { source: "/product.html", destination: "/product", permanent: true },
      { source: "/pricing.html", destination: "/pricing", permanent: true },
      { source: "/security.html", destination: "/security", permanent: true },
      { source: "/company.html", destination: "/company", permanent: true },
    ];
  },
};

export default nextConfig;
