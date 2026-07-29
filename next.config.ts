import type { NextConfig } from "next";

const NOMO_URL = "https://thenomocollection.com";

const nextConfig: NextConfig = {
  output: "standalone",
  async redirects() {
    return [
      // Direct booking has moved to its own site. Old property deep-links
      // (guests, QR codes, Hospitable "book direct" URLs) go straight there.
      {
        source: "/properties",
        destination: NOMO_URL,
        permanent: true,
        basePath: false,
      },
      {
        source: "/properties/:path*",
        destination: NOMO_URL,
        permanent: true,
        basePath: false,
      },
      // Generic on-site booking entry points → the branded interstitial.
      { source: "/book", destination: "/nomo-collection", permanent: true },
      { source: "/book-direct", destination: "/nomo-collection", permanent: true },
    ];
  },
};

export default nextConfig;
