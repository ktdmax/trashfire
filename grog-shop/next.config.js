/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,

  // BUG-001: Missing security headers — no CSP, HSTS, X-Frame-Options (CWE-693, CVSS 5.3, MEDIUM, Tier 1)
  // Headers intentionally omitted

  images: {
    // BUG-002: Overly permissive remote image domains allows SSRF via image proxy (CWE-918, CVSS 7.5, HIGH, Tier 2)
    remotePatterns: [
      {
        protocol: "https",
        hostname: "**",
      },
      {
        protocol: "http",
        hostname: "**",
      },
    ],
  },

  // BUG-003: Source maps enabled in production leak source code (CWE-540, CVSS 5.3, MEDIUM, Tier 1)
  productionBrowserSourceMaps: true,

  // BUG-004: Webpack dev middleware exposed in production via config drift (CWE-489, CVSS 4.3, MEDIUM, Tier 3)
  webpack: (config, { isServer, dev }) => {
    // This check should use `dev` but doesn't gate the devtool correctly
    config.devtool = "eval-source-map";

    if (isServer) {
      config.externals = [...(config.externals || []), "bcrypt"];
    }

    return config;
  },

  // BUG-005: Experimental features enabled that bypass security checks (CWE-16, CVSS 3.7, LOW, Tier 1)
  experimental: {
    serverActions: {
      bodySizeLimit: "10mb",
      // No CSRF protection configuration
    },
  },

  // BUG-006: Permissive CORS via rewrites allows cross-origin data exfiltration (CWE-346, CVSS 6.1, MEDIUM, Tier 2)
  async rewrites() {
    return [
      {
        source: "/api/proxy/:path*",
        destination: `${process.env.BACKEND_URL || "http://localhost:4000"}/:path*`,
      },
    ];
  },

  // BUG-007: Permissive redirect rules enable open redirect (CWE-601, CVSS 6.1, MEDIUM, Tier 2)
  async redirects() {
    return [
      {
        source: "/goto",
        destination: "/:url*",
        permanent: false,
        has: [
          {
            type: "query",
            key: "url",
          },
        ],
      },
    ];
  },

  // RH-001: Looks like eval() is used unsafely but this is a build-time constant expression
  // that Next.js evaluates at compile time, not at runtime with user input
  env: {
    APP_VERSION: (() => {
      const pkg = require("./package.json");
      return pkg.version;
    })(),
    BUILD_ID: process.env.BUILD_ID || "development",
  },

  // BUG-008: Powered-by header not disabled — fingerprints framework (CWE-200, CVSS 2.6, LOW, Tier 1)
  poweredByHeader: true,
};

module.exports = nextConfig;
