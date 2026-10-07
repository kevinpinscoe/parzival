#!/bin/sh
# nfpm postremove — runs after the RPM/DEB removes files.
#
# Just reloads systemd so it stops advertising units that no longer exist
# on disk. See preremove.sh for what's deliberately NOT done here (account/
# config/audit-log removal).
#
# Unlike preremove.sh, this needs no removal-only guard: package managers
# also run it during an upgrade (RPM $1 = 1, DEB $1 = upgrade), and a
# daemon-reload is correct, and harmless, in every one of those cases.
set -e

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi

exit 0
