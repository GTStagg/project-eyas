/** Subtle section divider — three centered dots flanked by hairlines.
 *  Picks up the brand red. Used between major sections of agentic pages. */
export default function SectionDivider({
  className = "",
}: {
  className?: string;
}) {
  return (
    <div
      role="separator"
      aria-hidden="true"
      className={`flex items-center justify-center gap-3 py-2 text-neutral-700 ${className}`}
    >
      <span className="h-px w-12 bg-gradient-to-r from-transparent to-neutral-800" />
      <span className="text-brand-600">●</span>
      <span className="text-brand-700">●</span>
      <span className="text-brand-600">●</span>
      <span className="h-px w-12 bg-gradient-to-l from-transparent to-neutral-800" />
    </div>
  );
}
