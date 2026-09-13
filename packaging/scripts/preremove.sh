#!/bin/sh
# nfpm preremove — runs before the RPM/DEB removes files.
#
# Stops and disables both units so a package removal doesn't leave a
# running process pointed at binaries that are about to disappear. Never
# removes the parzival-broker service account, /etc/parzival-broker, or
# /var/lib/parzival-broker — trust-root files and the audit log survive a
# package removal exactly as they survive `systemctl disable` today; an
# admin who wants a full purge does that separately and explicitly.
set -e

if [ -d /run/systemd/system ]; then
    systemctl disable --now parzival-broker.service >/dev/null 2>&1 || true
    systemctl disable --now check-parzival-broker.timer >/dev/null 2>&1 || true
fi

exit 0
