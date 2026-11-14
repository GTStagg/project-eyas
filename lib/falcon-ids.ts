// Falcon device ids (AIDs) are 32 hex characters. Ids that come back from
// Falcon are still interpolated into FQL filters, so each one is checked
// first: a value that doesn't match is dropped, never escaped.
const AID_RE = /^[0-9a-f]{32}$/i;

export function isAid(value: unknown): value is string {
  return typeof value === "string" && AID_RE.test(value);
}

export function onlyAids(values: Iterable<unknown>): string[] {
  const out: string[] = [];
  for (const v of values) if (isAid(v)) out.push(v);
  return out;
}
