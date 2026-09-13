#!/bin/sh
# nfpm postremove — runs after the RPM/DEB removes files.
#
# Just reloads systemd so it stops advertising units that no longer exist
# on disk. See preremove.sh for what's deliberately NOT done here (account/
# config/audit-log removal).
set -e

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi

exit 0
