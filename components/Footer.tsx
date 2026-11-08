import Link from "next/link";
import { ExternalLink } from "lucide-react";
import BrandMark from "./BrandMark";

/**
 * Global footer — added once via AppShell. Carries the unofficial disclaimer
 * on every page, plus a quiet vendor attribution. Single line on md+, stacks
 * on mobile. Visually quiet so it never competes with page content; the
 * red "Unofficial" tag is the only saturated note.
 */
export default function Footer() {
  return (
    <footer className="mt-auto border-t border-neutral-900 bg-black/80 px-4 py-3 backdrop-blur-sm">
      <div className="mx-auto flex max-w-screen-2xl flex-col items-center justify-between gap-2 text-[11px] text-neutral-500 md:flex-row">
        <div className="flex items-center gap-2">
          <BrandMark size={14} className="opacity-80" />
          <span className="font-mono uppercase tracking-[0.14em]">
            Eyas · Agentic console for CrowdStrike Falcon
          </span>
        </div>

        <div className="font-mono text-[10px] uppercase tracking-[0.18em] text-neutral-600">
          Not an official CrowdStrike product
        </div>

        <Link
          href="https://github.com/crowdstrike/falcon-mcp"
          target="_blank"
          rel="noreferrer"
          className="flex items-center gap-1 font-mono uppercase tracking-[0.14em] text-neutral-500 transition-colors hover:text-neutral-300"
        >
          Built on falcon-mcp · FalconPy · Claude
          <ExternalLink className="h-3 w-3" strokeWidth={2} />
        </Link>
      </div>
    </footer>
  );
}
