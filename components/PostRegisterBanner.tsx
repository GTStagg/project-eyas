"use client";
import { useEffect, useState } from "react";

/**
 * One-time banner rendered after a successful /register flow when the wizard
 * detected a configuration change that needs a server restart to fully apply
 * (currently only: falcon-extras enabled but venv not yet provisioned). Strips
 * the `postRegister` query param on dismiss so a refresh doesn't re-arm it.
 */
export default function PostRegisterBanner({ kind }: { kind: "restart-extras" }) {
  const [visible, setVisible] = useState(true);
  useEffect(() => {
    // Defensive: if the user reloads with the param still present we still
    // want the banner to appear. Strip on dismiss only.
  }, []);

  if (!visible) return null;

  function dismiss() {
    setVisible(false);
    if (typeof window !== "undefined") {
      const url = new URL(window.location.href);
      url.searchParams.delete("postRegister");
      window.history.replaceState({}, "", url.toString());
    }
  }

  if (kind === "restart-extras") {
    return (
      <div className="border-b border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm text-amber-200">
        <div className="mx-auto flex max-w-5xl items-center justify-between gap-4">
          <div>
            <strong className="font-semibold">Configuration saved.</strong>{" "}
            Restart the server to finish installing the falcon-extras sidecar
            (host containment, RTR scripts, IR workflow). The Python venv is
            created on launch from bundled wheels — until you restart, those
            features won&apos;t be available.
          </div>
          <button
            type="button"
            onClick={dismiss}
            className="shrink-0 rounded-md border border-amber-500/40 bg-amber-500/10 px-2.5 py-1 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-amber-100 hover:bg-amber-500/20"
          >
            Dismiss
          </button>
        </div>
      </div>
    );
  }
  return null;
}
