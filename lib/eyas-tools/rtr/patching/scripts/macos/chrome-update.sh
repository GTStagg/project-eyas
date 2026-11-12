# Google Chrome on macOS: vendor PKG download + installer -pkg.
URL="https://dl.google.com/chrome/mac/universal/stable/gcem/GoogleChrome.pkg"
TMP="/tmp/falcon-extras-chrome-$$.pkg"

echo "[falcon-extras] downloading Chrome PKG from $URL"
curl -fsSL --retry 3 --max-time 300 -o "$TMP" "$URL"
SIZE=$(stat -f %z "$TMP")
echo "[falcon-extras] downloaded $SIZE bytes -> $TMP"
if [ "$SIZE" -lt 1024 ]; then
    echo "[falcon-extras] error: download too small" >&2
    rm -f "$TMP"
    exit 5
fi

echo "[falcon-extras] installing Chrome PKG"
installer -pkg "$TMP" -target /
rc=$?
rm -f "$TMP"
echo "[falcon-extras] chrome-update exit=$rc host=$(hostname)"
exit $rc
