apt_upgrade_packages openssh-server openssh-client openssh-sftp-server
rc=$?
# OpenSSH server upgrade restarts the daemon; existing sessions stay open
# but new connections briefly fail during restart.
echo "[falcon-extras] apt-openssh exit=$rc host=$(hostname)"
exit $rc
