apt_upgrade_packages apache2 apache2-bin apache2-data apache2-utils
rc=$?
echo "[falcon-extras] apt-apache2 exit=$rc host=$(hostname)"
exit $rc
