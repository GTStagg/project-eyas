/* eslint-disable @next/next/no-img-element */

import BrandMark from "./BrandMark";
import Wordmark from "./Wordmark";
import { SHOW_CROWDSTRIKE_LOCKUP } from "./attribution";

/**
 * Login / register hero. Eyas leads with its own identity (BrandMark
 * + Wordmark + tagline). Data-source attribution sits below it (the
 * CrowdStrike lockup image, or text when SHOW_CROWDSTRIKE_LOCKUP is off) and a
 * small "Unofficial" line carries the disclaimer — there's no other disclosure on the
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

      {/* Data-source attribution: the lockup image, or text when it's off (the
          logo is CrowdStrike's trademark and isn't redistributed). */}
      {SHOW_CROWDSTRIKE_LOCKUP && (
        <img src="/crowdstrike-lockup.png" alt="CrowdStrike" className="mt-1 h-12 w-auto" />
      )}

      <p className="font-mono text-[10px] uppercase tracking-[0.22em] text-neutral-600">
        {SHOW_CROWDSTRIKE_LOCKUP ? "" : "Data sourced from CrowdStrike Falcon · "}Not an official
        CrowdStrike product
      </p>
    </div>
  );
}
