import BrandMark from "./BrandMark";
import Wordmark from "./Wordmark";

/**
 * Login / register hero. Eyas leads with its own identity (BrandMark
 * + Wordmark + tagline). A small data-source and "Unofficial" line sits below
 * it and carries the disclaimer — there's no other disclosure on the
 * unauthed pages, so this is the load-bearing one. Authed pages get the
 * disclaimer from the global footer instead.
 */
export default function ClassificationBanner() {
  return (
    <div className="mb-8 flex flex-col items-center gap-5 text-center">
      {/* Eyas identity */}
      <div className="flex flex-col items-center gap-3">
        <BrandMark size={48} />
        <Wordmark tier="stacked" className="items-center" />
        <p className="font-mono text-[11px] uppercase tracking-[0.22em] text-neutral-500">
          Agentic console for CrowdStrike Falcon
        </p>
      </div>

      <p className="font-mono text-[10px] uppercase tracking-[0.22em] text-neutral-600">
        Data sourced from CrowdStrike Falcon · Not an official CrowdStrike product
      </p>
    </div>
  );
}
