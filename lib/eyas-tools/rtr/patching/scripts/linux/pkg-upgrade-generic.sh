# Generic single-package upgrade for any Linux host (apt / dnf / yum). The
# package name is supplied via the rendered $PACKAGE shell variable from
# the params block. Validation lives in library.py: the package name must
# match ^[a-z0-9][a-z0-9.+-]{0,49}$ which covers both Debian and RPM
# naming -- no shell metacharacters survive the regex.
#
# Distro detection happens inside pkg_upgrade_packages: apt-get -> dnf ->
# yum, first found wins. Same script body works on Ubuntu, Debian,
# RHEL 7/8/9, Rocky, Alma, Fedora, Amazon Linux 2/2023.

if [ -z "${PACKAGE:-}" ]; then
    echo "[eyas] error: PACKAGE not set; resolver did not supply package param" >&2
    exit 3
fi

pkg_upgrade_packages "$PACKAGE"
rc=$?
echo "[eyas] pkg-upgrade-generic package=$PACKAGE exit=$rc host=$(hostname)"
exit $rc
