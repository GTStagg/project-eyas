import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  // Files Next.js's import tracer can't see, opted into the standalone bundle:
  //  - Migration .sql files are read via fs at boot.
  //  - pdfjs (via pdf-parse) loads its worker at runtime by resolving a sibling
  //    path string, which the tracer can't follow — so `pdf.worker.mjs` is left
  //    out and the first PDF ingest fails with "Setting up fake worker failed".
  //    Including the legacy build dir ships the worker alongside pdf.mjs.
  outputFileTracingIncludes: {
    "/": [
      "./lib/db/migrations/**/*.sql",
      "./node_modules/pdfjs-dist/legacy/build/pdf.worker.mjs",
    ],
  },
  // better-sqlite3 is a native module — exclude from the server bundle
  // and let Node resolve it from node_modules at runtime. mammoth + pdf-parse
  // (knowledge-base document text extraction) are kept external too: both pull
  // in heavy parser/worker assets that are best resolved from node_modules at
  // runtime rather than traced into the webpack bundle.
  serverExternalPackages: ["better-sqlite3", "mammoth", "pdf-parse"],
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
