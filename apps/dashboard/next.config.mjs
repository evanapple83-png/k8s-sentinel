/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // The dashboard talks to the orchestrator API over HTTP (CORS-enabled), so it
  // bundles no Node-only backend code. Lint is run separately, not at build.
  eslint: { ignoreDuringBuilds: true },
};

export default nextConfig;
