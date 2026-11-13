# Distro-agnostic package-manager dispatcher. Supports apt (Debian/Ubuntu),
# dnf (RHEL 8+ / Rocky / Alma / Fedora / Amazon Linux 2023+), and yum
# (RHEL 7 / Amazon Linux 2 -- kept for the long tail; dnf has been the
# Red Hat default since RHEL 8 in 2019).
#
# Detection precedence: apt -> dnf -> yum. The first one found wins. Hosts
# rarely have more than one installed; when they do, the more modern
# manager is preferred.
#
# Public surface:
#   pkg_upgrade_packages <pkg> [<pkg> ...]
#       Resolve the right manager and upgrade the named packages.
#       Returns the underlying command's exit status, or 4 if no
#       supported manager is present.

pkg_upgrade_packages() {
    local pkgs=("$@")
    if [ "${#pkgs[@]}" -eq 0 ]; then
        echo "[eyas] error: no packages supplied" >&2
        return 3
    fi

    if command -v apt-get >/dev/null 2>&1; then
        echo "[eyas] using apt-get (apt-get update; apt-get install --only-upgrade)"
        apt-get update -qq
        apt-get install -y --only-upgrade "${pkgs[@]}"
        local rc=$?
        echo "[eyas] apt-get install exit=$rc"
        return $rc
    fi

    if command -v dnf >/dev/null 2>&1; then
        echo "[eyas] using dnf (dnf upgrade -y)"
        # `dnf upgrade <pkg>` is a no-op (success) when the package is
        # already at the latest version, which matches apt --only-upgrade
        # semantics. --setopt=install_weak_deps=False keeps the upgrade
        # tight without pulling Recommends.
        dnf upgrade -y --setopt=install_weak_deps=False "${pkgs[@]}"
        local rc=$?
        echo "[eyas] dnf upgrade exit=$rc"
        return $rc
    fi

    if command -v yum >/dev/null 2>&1; then
        echo "[eyas] using yum (yum update -y)"
        yum update -y "${pkgs[@]}"
        local rc=$?
        echo "[eyas] yum update exit=$rc"
        return $rc
    fi

    echo "[eyas] error: no supported package manager (apt-get / dnf / yum) on this host" >&2
    return 4
}

