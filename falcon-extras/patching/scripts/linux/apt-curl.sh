# curl + libcurl4 covers both the CLI and the shared library that everything
# on the host links against (the actual Spotlight finding for "Libcurl").
apt_upgrade_packages curl libcurl4 libcurl3-gnutls
rc=$?
echo "[falcon-extras] apt-curl exit=$rc host=$(hostname)"
exit $rc
