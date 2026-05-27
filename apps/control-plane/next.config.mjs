import { fileURLToPath } from 'node:url';

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Pin the workspace root so Next doesn't pick up an unrelated lockfile higher
  // up the tree (this app lives in a pnpm monorepo).
  turbopack: { root: fileURLToPath(new URL('../..', import.meta.url)) },
  // Lint is run separately in CI, not at build time.
  eslint: { ignoreDuringBuilds: true },
};

export default nextConfig;
