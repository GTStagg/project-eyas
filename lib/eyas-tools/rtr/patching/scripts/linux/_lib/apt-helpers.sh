# Helper: apt-get update with retry, then install --only-upgrade for one or
# more packages. Supports apt-based distros only (Debian/Ubuntu).
apt_upgrade_packages() {
    local pkgs=("$@")
    if [ "${#pkgs[@]}" -eq 0 ]; then
        echo "[falcon-extras] error: no packages supplied" >&2
        return 3
    fi
    if ! command -v apt-get >/dev/null 2>&1; then
        echo "[falcon-extras] error: apt-get not present (host is not Debian/Ubuntu?)" >&2
        return 4
    fi

    echo "[falcon-extras] apt-get update"
    apt-get update -qq

    echo "[falcon-extras] installing --only-upgrade ${pkgs[*]}"
    apt-get install -y --only-upgrade "${pkgs[@]}"
    local rc=$?
    echo "[falcon-extras] apt-get install exit=$rc"
    return $rc
}
