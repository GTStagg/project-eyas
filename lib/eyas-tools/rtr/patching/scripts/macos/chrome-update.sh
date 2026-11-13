# Google Chrome on macOS: vendor PKG download + installer -pkg.
URL="https://dl.google.com/chrome/mac/universal/stable/gcem/GoogleChrome.pkg"
TMP="/tmp/falcon-extras-chrome-$$.pkg"

echo "[eyas] downloading Chrome PKG from $URL"
curl -fsSL --retry 3 --max-time 300 -o "$TMP" "$URL"
SIZE=$(stat -f %z "$TMP")
echo "[eyas] downloaded $SIZE bytes -> $TMP"
if [ "$SIZE" -lt 1024 ]; then
    echo "[eyas] error: download too small" >&2
    rm -f "$TMP"
    exit 5
fi

echo "[eyas] installing Chrome PKG"
installer -pkg "$TMP" -target /
rc=$?
rm -f "$TMP"
echo "[eyas] chrome-update exit=$rc host=$(hostname)"
exit $rc
