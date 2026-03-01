import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // API calls go to api.patchpilot.com only.
  // Hard boundary: Never call Supabase directly from the browser.
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;
