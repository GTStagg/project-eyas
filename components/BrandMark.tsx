/**
 * Falcon-A mark — capital "A" (for Agentic) with a falcon spreading its
 * wings out from the apex. The two A-strokes anchor the letterform; the
 * wings sweep back-and-up asymmetrically (right wing slightly elevated)
 * to imply forward motion. White eye-glint at the apex sits in the
 * negative space inside the bird's head. Reads as letter at small sizes,
 * resolves to letter+falcon at 22px+. Trademark-distinct from the
 * official CrowdStrike falcon — swap this file for the licensed asset
 * when available.
 */
export default function BrandMark({
  size = 22,
  className = "",
}: {
  size?: number;
  className?: string;
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={`brand-glow ${className}`}
      aria-hidden="true"
    >
      <defs>
        <linearGradient id="bm-a" x1="0" y1="32" x2="32" y2="0" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#7f1d1d" />
          <stop offset="0.5" stopColor="#dc2626" />
          <stop offset="1" stopColor="#ef4444" />
        </linearGradient>
        <linearGradient id="bm-wing" x1="0" y1="8" x2="32" y2="2" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#7f1d1d" />
          <stop offset="0.6" stopColor="#dc2626" />
          <stop offset="1" stopColor="#ef4444" />
        </linearGradient>
      </defs>

      {/* Left wing — back-swept, sweeps from apex out to upper-left */}
      <path d="M16 8 L4 3 L7 8 L13 11 Z" fill="url(#bm-wing)" />
      {/* Right wing — back-swept, slightly elevated for forward motion */}
      <path d="M16 8 L29 1 L25 7 L19 11 Z" fill="url(#bm-wing)" />

      {/* A — left diagonal stroke */}
      <path d="M5 29 L11 29 L18 11 L14 11 Z" fill="url(#bm-a)" />
      {/* A — right diagonal stroke */}
      <path d="M21 29 L27 29 L18 11 L14 11 Z" fill="url(#bm-a)" />
      {/* A — apex peak (closes the strokes into a sharp point) */}
      <path d="M13 11 L19 11 L16 6 Z" fill="url(#bm-a)" />
      {/* A — crossbar */}
      <path d="M10 19 L22 19 L21 22 L11 22 Z" fill="url(#bm-a)" />

      {/* Beak — small angular point breaking forward from the apex */}
      <path d="M16 6 L20 7 L17 10 Z" fill="#ef4444" />
      {/* Eye glint — single bright pixel inside the falcon's head */}
      <circle cx="17.5" cy="7.5" r="0.7" fill="#ffffff" opacity="0.95" />
    </svg>
  );
}
