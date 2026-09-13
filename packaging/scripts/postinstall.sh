#!/bin/sh
# nfpm postinstall — runs after the RPM/DEB unpacks files.
#
# Creates the parzival-broker service account declaratively (never
# useradd by hand), fixes up group ownership on the three directories this
# package itself ships under /etc/parzival-broker, and reloads systemd so
# the newly-installed units are visible to `systemctl`. Deliberately does
# NOT enable or start the service — bringing a broker online needs
# /etc/parzival-broker/environment and the trust-root files (authz.json,
# consumers/, profiles/, openbao-secret-id.cred) in place first, none of
# which a package can generate; see packaging/README.md and INSTALL.md.
set -e

if command -v systemd-sysusers >/dev/null 2>&1; then
    systemd-sysusers /usr/lib/sysusers.d/parzival-broker.conf || true
fi

# nfpm unpacks /etc/parzival-broker and its consumers/profiles
# subdirectories as root:root (dpkg/rpm apply ownership before this script
# runs, so a static `file_info.group: parzival-broker` in .goreleaser.yml
# cannot work — the group does not exist yet at unpack time). Fix the group
# now that systemd-sysusers has just created it, matching the same
# root:parzival-broker 0750 ownership contract documented in
# packaging/README.md and INSTALL.md:
# root retains write authority, parzival-broker gets read+traverse only.
#
# Deliberately NOT recursive (`chgrp -R`) and touches only these three
# directory entries themselves — never their contents. Any file an
# administrator has placed inside consumers/ or profiles/ (or authz.json,
# or openbao-secret-id.cred, both siblings of these directories) is
# untouched: this package has no ownership contract over administrator-
# created trust-root files, only over the structure it shipped. Safe to
# re-run on every upgrade — chgrp/chmod are idempotent, and running them
# again on an already-correct directory changes nothing.
#
# Deliberately NOT `|| true`: unlike systemd-sysusers/daemon-reload above
# (best-effort, skippable outside a systemd host), a failure here leaves
# the broker unable to start correctly (the trust-root verifier refuses a
# directory that isn't actually root:parzival-broker) — better to abort
# the install/upgrade loudly than finish it silently broken.
if getent group parzival-broker >/dev/null 2>&1; then
    for d in /etc/parzival-broker /etc/parzival-broker/consumers /etc/parzival-broker/profiles; do
        if [ -d "$d" ]; then
            chgrp parzival-broker "$d"
            chmod 0750 "$d"
        fi
    done
fi

# /run/systemd/system existing is the standard way to tell whether systemd
# is actually the running init (as opposed to, say, a container image build
# with no init running at all) — reloading against a non-running systemd
# would just fail loudly for no benefit.
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi

exit 0
