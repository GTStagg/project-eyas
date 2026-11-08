"use client";

// Last-resort boundary: catches errors in app/layout.tsx itself. Must render
// its own <html>/<body>. Per-page errors are caught by app/error.tsx instead.
export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <html lang="en">
      <body
        style={{
          background: "#0a0a0a",
          color: "#e5e5e5",
          fontFamily: "system-ui, sans-serif",
          padding: "4rem 1.5rem",
          minHeight: "100vh",
        }}
      >
        <main style={{ maxWidth: "40rem", margin: "0 auto" }}>
          <h1 style={{ fontSize: "1.25rem", fontWeight: 600, color: "#fca5a5" }}>
            The console crashed.
          </h1>
          <p style={{ marginTop: "0.5rem", fontSize: "0.875rem" }}>
            {error.message || "An unexpected error occurred."}
          </p>
          {error.digest ? (
            <p style={{ marginTop: "0.25rem", fontSize: "0.75rem", color: "#737373" }}>
              digest: {error.digest}
            </p>
          ) : null}
          <button
            type="button"
            onClick={reset}
            style={{
              marginTop: "1.25rem",
              padding: "0.5rem 1rem",
              background: "#171717",
              color: "#e5e5e5",
              border: "1px solid #404040",
              borderRadius: "0.5rem",
              cursor: "pointer",
              fontSize: "0.875rem",
            }}
          >
            Reload
          </button>
        </main>
      </body>
    </html>
  );
}
