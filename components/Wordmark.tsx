/**
 * Eyas wordmark. Three size tiers, all optional:
 *   - primary: "EYAS" tracked uppercase, large — login / hero use
 *   - stacked: "EYAS" large — sidebar / login use
 *   - compact: "EYAS" inline, single line — topbars and tight rows
 * Sized via the `tier` prop. Renders as text spans (not SVG) so it scales
 * with font hinting at small sizes.
 *
 * "Eyas" is a young falcon being trained for falconry — fits the
 * unofficial/reference posture (raised on the same craft as Falcon, not
 * the same bird). The "A" of EYAS pairs visually with the BrandMark falcon
 * silhouette.
 */
export default function Wordmark({
  tier = "stacked",
  className = "",
}: {
  tier?: "compact" | "stacked" | "primary";
  className?: string;
}) {
  if (tier === "compact") {
    return (
      <span
        className={`inline-flex items-baseline font-sans ${className}`}
        aria-label="Eyas"
      >
        <span className="text-[15px] font-extrabold uppercase leading-none tracking-[0.18em] text-white">
          EYAS
        </span>
      </span>
    );
  }
  if (tier === "primary") {
    return (
      <span
        className={`inline-block font-sans text-[18px] font-extrabold uppercase leading-none tracking-[0.18em] text-white ${className}`}
        aria-label="Eyas"
      >
        EYAS
      </span>
    );
  }
  // stacked — primary use in sidebar header / login
  return (
    <span
      className={`inline-flex flex-col font-sans leading-none ${className}`}
      aria-label="Eyas"
    >
      <span className="text-[18px] font-extrabold uppercase tracking-[0.20em] text-white">
        EYAS
      </span>
    </span>
  );
}
