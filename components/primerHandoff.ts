// Deep-link primer hand-off into chat. Short primers ride the URL; long ones
// (host-level triage, multi-detection campaigns) blow past Node's
// max-http-header-size and surface as HTTP 431. Stash those in sessionStorage
// and put a sentinel in the URL — Chat.tsx pulls them back out on mount.

const STASH_KEY = "chat:primer";
export const PRIMER_STASH_SENTINEL = "stash";
const URL_SAFE_LIMIT = 1500;

export function buildPrimerHref(primer: string): string {
  if (typeof window !== "undefined" && primer.length > URL_SAFE_LIMIT) {
    try {
      window.sessionStorage.setItem(STASH_KEY, primer);
      return `/?primer=${PRIMER_STASH_SENTINEL}`;
    } catch {
      // sessionStorage unavailable — fall through to URL form.
    }
  }
  return `/?primer=${encodeURIComponent(primer)}`;
}

export function readStashedPrimer(): string | null {
  if (typeof window === "undefined") return null;
  try {
    const v = window.sessionStorage.getItem(STASH_KEY);
    if (v) window.sessionStorage.removeItem(STASH_KEY);
    return v;
  } catch {
    return null;
  }
}
