#!/bin/sh
# nfpm preremove — runs before the RPM/DEB removes files.
#
# Stops and disables both units so a package removal doesn't leave a
# running process pointed at binaries that are about to disappear. Never
# removes the parzival-broker service account, /etc/parzival-broker, or
# /var/lib/parzival-broker — trust-root files and the audit log survive a
# package removal exactly as they survive `systemctl disable` today; an
# admin who wants a full purge does that separately and explicitly.
#
# Removal only, never an upgrade. Both package managers run the OLD
# package's remove script during an upgrade too, and nfpm embeds this file
# verbatim, so $1 is the package manager's own argument:
#
#   RPM %preun  $1 = instances left after the transaction:
#                    0 on erase, 1 (or more) on upgrade
#   DEB prerm   $1 = remove | deconfigure            (package going away)
#                    upgrade | failed-upgrade        (package being replaced)
#
# Before this guard, an upgrade stopped and disabled a live, enabled broker
# and its health-check timer, and nothing brought them back: postinstall
# never enables or starts the broker. A package carrying the unguarded
# version (v0.2.0 and earlier) still does that when it is the one being
# upgraded FROM — its own copy of this script is what runs. See INSTALL.md,
# "Upgrading".
#
# No argument at all is treated as a removal, which is what this script
# did unconditionally before, so running it by hand keeps its old meaning.
set -e

case "${1-}" in
    0 | remove | deconfigure | "") ;;
    *) exit 0 ;;
esac

if [ -d /run/systemd/system ]; then
    systemctl disable --now parzival-broker.service >/dev/null 2>&1 || true
    systemctl disable --now check-parzival-broker.timer >/dev/null 2>&1 || true
fi

exit 0
