import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  // No "X-Powered-By: Next.js" banner.
  poweredByHeader: false,
  // Files Next.js's import tracer can't see, opted into the standalone bundle:
  //  - Migration .sql files are read via fs at boot.
  //  - The RTR script library (manifests + scripts) is read via fs when a
  //    patch or cleanup tool renders a script.
  //  - pdfjs (via pdf-parse) loads its worker at runtime by resolving a sibling
  //    path string, which the tracer can't follow — so `pdf.worker.mjs` is left
  //    out and the first PDF ingest fails with "Setting up fake worker failed".
  //    Including the legacy build dir ships the worker alongside pdf.mjs.
  outputFileTracingIncludes: {
    "/": [
      "./lib/db/migrations/**/*.sql",
      "./lib/eyas-tools/rtr/*/manifest.json",
      "./lib/eyas-tools/rtr/*/scripts/**/*",
      "./node_modules/pdfjs-dist/legacy/build/pdf.worker.mjs",
    ],
  },
  // better-sqlite3 is a native module — exclude from the server bundle
  // and let Node resolve it from node_modules at runtime. mammoth + pdf-parse
  // (knowledge-base document text extraction) are kept external too: both pull
  // in heavy parser/worker assets that are best resolved from node_modules at
  // runtime rather than traced into the webpack bundle.
  serverExternalPackages: ["better-sqlite3", "mammoth", "pdf-parse"],
  // Browser hardening for every response. The console is never meant to be
  // framed, and an approval card's Allow button is the target a framing page
  // would aim at, so framing is refused outright (frame-ancestors is the
  // modern control, X-Frame-Options covers older browsers).
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "Content-Security-Policy", value: "frame-ancestors 'none'" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "same-origin" },
        ],
      },
    ];
  },
  async redirects() {
    return [
      // /pivot consolidates artifact lookup + execution lineage. Old deep
      // links (row-level "Triage hash" on /detections, /?primer= hand-offs,
      // bookmarks) keep working — query string carries through.
      { source: "/lookup", destination: "/pivot", permanent: false },
      {
        source: "/threat-graph",
        destination: "/pivot?mode=lineage",
        permanent: false,
      },
      // Host group posture folded into /hosts as a collapsible panel.
      { source: "/host-groups", destination: "/hosts", permanent: false },
    ];
  },
};

export default nextConfig;
