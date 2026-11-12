# macOS security + recommended updates. --no-scan reuses Apple's last scan
# result, so a softwareupdate -l in the resolve flow surfaces what will be
# installed. We do NOT pass --restart by default; reboot policy is the
# operator's call (would need a separate gated tool to coordinate).
echo "[falcon-extras] available updates:"
softwareupdate -l 2>&1 || true

echo "[falcon-extras] installing recommended updates"
softwareupdate -i -r --agree-to-license
rc=$?
echo "[falcon-extras] softwareupdate exit=$rc host=$(hostname)"
exit $rc
