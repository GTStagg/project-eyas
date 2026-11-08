#!/usr/bin/env bash
# Pull live Spotlight remediations from the dev server and bucket by vendor.
set -euo pipefail
cd "$(dirname "$0")/../../.."

URL="${VULNS_URL:-http://localhost:3000/vulnerabilities?mode=newest&limit=2000}"
TMP="${TMPDIR:-/tmp}/falcon-remediations-$$.html"
COOKIE_FILE="${TMPDIR:-/tmp}/falcon-audit-cookie-$$.txt"
trap 'rm -f "$TMP" "$COOKIE_FILE"' EXIT

# Mint an iron-session cookie from AUTH_SESSION_SECRET so the dev server's
# auth gate doesn't bounce us to /login. Same pattern as tests/auth.setup.ts.
# Reads .env.local first (Next.js precedence), then .env. If sealing fails
# (no secret found, missing iron-session dep) we fall back to a cookieless
# curl -- works on a server without auth enabled.
if node -e '
  const fs = require("fs"), path = require("path");
  const { sealData } = require("iron-session");
  let secret;
  for (const file of [".env.local", ".env"]) {
    const envPath = path.join(process.cwd(), file);
    if (!fs.existsSync(envPath)) continue;
    const line = fs.readFileSync(envPath, "utf8").split("\n")
      .find(l => l.startsWith("AUTH_SESSION_SECRET="));
    if (!line) continue;
    let s = line.split("=").slice(1).join("=").trim();
    if (/^["'\''].*["'\'']$/.test(s)) s = s.slice(1, -1);
    if (s.length >= 32) { secret = s; break; }
  }
  if (!secret) process.exit(2);
  sealData({ authenticated: true, loginAt: new Date().toISOString() },
           { password: secret, ttl: 7 * 24 * 3600 })
    .then(s => fs.writeFileSync(process.argv[1], "falcon_mcp_session=" + s));
' "$COOKIE_FILE" 2>/dev/null; then
    CURL_COOKIE=(--cookie "$(cat "$COOKIE_FILE")")
else
    CURL_COOKIE=()
fi

echo "[audit] fetching $URL"
if ! curl -sSf "${CURL_COOKIE[@]}" "$URL" -o "$TMP"; then
    echo "[audit] FAIL: dev server not reachable. Start it with 'npm run dev' first." >&2
    exit 2
fi
SIZE=$(wc -c < "$TMP")
echo "[audit] fetched $SIZE bytes"
if [ "$SIZE" -lt 100000 ]; then
    echo "[audit] page is suspiciously small -- the route may be 500'ing or auth-redirecting." >&2
    exit 3
fi

python3 - "$TMP" <<'PY'
import sys, re, json, pathlib, collections
sys.path.insert(0, "falcon-extras")
from patching import library

html = open(sys.argv[1], encoding="utf-8", errors="replace").read()

# Recommended-remediation strings appear in the rendered page in two flavours:
#   "Update <Vendor> <Product> to <version>..."
#   "Install patch for <OS>: Security Update KB..."
# We extract both and discard CVE-description prose that happens to start with
# "Update the ..." / "Remove the ..." (these are kernel changelog snippets, not
# remediation entities).
patterns = [
    r"Update [A-Z][^<\"]{0,80}",
    r"Install patch for [^<\"]{0,120}",
    r"Upgrade [A-Z][^<\"]{0,80}",
]
hits = []
for pat in patterns:
    hits.extend(re.findall(pat, html))

# Strip CVE-description noise.
NOISE = re.compile(
    r"^(Update|Remove|Apply|Upgrade) (the\b|separate |rst_mask|IRQF_NO_THREAD|GC HW)",
    re.IGNORECASE,
)
hits = [h for h in hits if not NOISE.match(h)]
# Also drop "Update Guide" / "Update Service" / "Update Options" — these are CVE prose, not remediations.
hits = [h for h in hits if not re.match(r"^Update (Guide|Service|Options)\b", h)]

counts = collections.Counter(hits)

# Bucket by best-effort (vendor, product) extraction.
def split_remediation(s):
    s = s.replace("\\u003e", ">").strip().rstrip("\\").strip()
    # "Install patch for <OS>: Security Update KBxxxx" -> ("Microsoft", <OS>)
    m = re.match(r"Install patch for (.+?)(?::|$)", s)
    if m:
        return ("Microsoft", m.group(1).strip())
    # Bare "Update KB1234567" -> Windows cumulative; route to win-update-install bucket.
    m = re.match(r"Update (KB\d{6,7})\b", s)
    if m:
        return ("Microsoft", "Microsoft Windows")
    # "Update <Vendor> <Product> to ..."  / "Update <Vendor> <Product>\\"
    m = re.match(r"(?:Update|Upgrade)\s+(.+?)(?:\s+to\b| version\b|\s+by\b|$)", s)
    if not m:
        return ("?", s)
    rest = m.group(1).strip()
    # Heuristic: first token is vendor if it's a known vendor word, else first 2 tokens.
    KNOWN_VENDORS = ("Mozilla", "Microsoft", "Adobe", "Google", "Oracle", "Apple",
                     "Notepad++", "Don", "VideoLAN", "Zoom", "RARLAB", "WinRAR",
                     "Igor", "7-Zip", "Haxx", "curl", "OpenSSH", "Apache",
                     "Simon", "PuTTY", "Git", "Eclipse", "Adoptium", "Temurin")
    toks = rest.split()
    if toks and toks[0] in KNOWN_VENDORS:
        vendor = toks[0]
        product = " ".join(toks[1:]) if len(toks) > 1 else toks[0]
    else:
        vendor = toks[0] if toks else "?"
        product = " ".join(toks[:3]) if len(toks) >= 2 else rest
    return (vendor, product)

# Aggregate by (vendor, normalized-product-prefix). Strip trailing version digits
# so "Mozilla Firefox 53" / "Mozilla Firefox 150" / "Mozilla FireFox" all collapse
# to the same bucket.
def norm_product(p):
    p = re.sub(r"\s+to\s+.*$", "", p)
    p = re.sub(r"\s+\d[\d.]*\s*$", "", p)
    p = re.sub(r"\s+(Server|Workstation|x64|x86)\s*$", "", p, flags=re.IGNORECASE)
    p = re.sub(r"\(.*?\)", "", p).strip()
    # Collapse Office product family
    if re.match(r"Microsoft (Word|Excel|Outlook|PowerPoint|OneNote|Access|Office)", p, re.IGNORECASE):
        return "Microsoft Office (family)"
    if p.lower().startswith("microsoft windows"):
        return "Microsoft Windows"
    if re.match(r"Mozilla\s+Fire[Ff]ox", p):
        return "Mozilla Firefox"
    return p

buckets = collections.defaultdict(int)
representatives = {}
for hit, n in counts.items():
    vendor, product = split_remediation(hit)
    key = (vendor, norm_product(product))
    buckets[key] += n
    representatives.setdefault(key, hit)

covered, uncovered = [], []
for (vendor, product), n in sorted(buckets.items(), key=lambda x: -x[1]):
    # Pick the OS family by vendor when obvious.
    os_filter = "windows"
    if vendor in ("Apache", "OpenSSH", "Haxx", "curl"):
        os_filter = "linux"
    if vendor == "Apple":
        os_filter = "macos"
    # Real Spotlight product strings sometimes carry the vendor prefix
    # ("Adobe Reader") and sometimes don't ("Libcurl"). Bucketing strips
    # variant suffixes but can't know which form the manifest pattern wants,
    # so try both and accept the first match.
    candidates = [product]
    if not product.lower().startswith(vendor.lower()):
        candidates.append(f"{vendor} {product}".strip())
    match = next((m for c in candidates if (m := library.match_remediation(vendor, c, os_filter))), None)
    if match:
        covered.append((n, vendor, product, match["id"]))
    else:
        uncovered.append((n, vendor, product, representatives[(vendor, product)]))

print(f"\n=== Covered ({len(covered)} buckets) ===")
print(f"{'count':>6}  {'vendor':<22}  {'product':<40}  script")
for n, v, p, sid in covered[:30]:
    print(f"{n:>6}  {v:<22}  {p:<40}  {sid}")

print(f"\n=== Uncovered ({len(uncovered)} buckets) -- candidates for next batch ===")
print(f"{'count':>6}  {'vendor':<22}  {'product':<40}  example")
for n, v, p, ex in uncovered[:40]:
    ex_short = ex if len(ex) < 60 else ex[:57] + "..."
    print(f"{n:>6}  {v:<22}  {p:<40}  {ex_short}")

print(f"\nTotal remediation rows: {sum(counts.values())}")
print(f"Distinct buckets: {len(buckets)}  covered: {len(covered)}  uncovered: {len(uncovered)}")
PY
