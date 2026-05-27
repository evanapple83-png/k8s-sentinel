import { fileURLToPath } from 'node:url';

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Pin the workspace root so Next doesn't pick up an unrelated lockfile higher
  // up the tree (this app lives in a pnpm monorepo).
  turbopack: { root: fileURLToPath(new URL('../..', import.meta.url)) },
};

export default nextConfig;
