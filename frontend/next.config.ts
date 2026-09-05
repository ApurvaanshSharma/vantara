import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Standalone output: bundles only the files the app actually needs into
  // .next/standalone, instead of requiring node_modules copied wholesale
  // into the final Docker image. Meaningfully smaller image, faster
  // deploys — the standard pattern for Next.js in Docker.
  output: "standalone",
};

export default nextConfig;
