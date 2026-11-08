"use client";

import { useEffect } from "react";

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error("[falcon-mcp] page error:", error);
  }, [error]);

  return (
    <main className="mx-auto max-w-2xl px-6 py-16">
      <div className="rounded-lg border border-red-500/30 bg-red-950/20 p-6">
        <h1 className="font-display text-xl font-semibold text-red-200">
          Something went wrong rendering this page.
        </h1>
        <p className="mt-2 text-sm text-neutral-300">
          {error.message || "An unexpected error occurred."}
        </p>
        {error.digest ? (
          <p className="mt-1 font-mono text-xs text-neutral-500">
            digest: {error.digest}
          </p>
        ) : null}
        <div className="mt-5 flex gap-2">
          <button
            type="button"
            onClick={reset}
            className="rounded-lg border border-neutral-700 bg-neutral-900 px-4 py-2 text-sm text-neutral-100 hover:bg-neutral-800"
          >
            Try again
          </button>
          <a
            href="/"
            className="rounded-lg border border-neutral-700 bg-neutral-900 px-4 py-2 text-sm text-neutral-100 hover:bg-neutral-800"
          >
            Home
          </a>
        </div>
      </div>
    </main>
  );
}
