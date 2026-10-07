#!/usr/bin/env bash
#
# test-package-scripts.sh — check what the RPM/DEB maintainer scripts do to
# the broker's systemd units on install, upgrade, and removal.
#
# Usage: scripts/test-package-scripts.sh [--packages <dist-dir>]
#
# Without arguments it runs packaging/scripts/*.sh under every argument RPM
# and dpkg pass them, with `systemctl` (and the other system commands they
# call) replaced by stubs that only record their arguments, and asserts on
# what was recorded. Nothing on the host is touched, and it needs neither
# root nor a running systemd: each script runs from a temporary copy whose
# /run/systemd/system check points at a temporary directory instead.
#
# With --packages, it additionally checks that every .rpm and .deb in
# <dist-dir> embeds the three scripts byte-for-byte — the property that
# makes $1 the package manager's own argument, and so the property the
# first half's argument tables depend on. Needs rpm (rpm -qp --scripts) and
# dpkg-deb.
#
# The case that matters most: an upgrade must never stop or disable the
# broker. Every package manager runs the OLD package's remove scripts during
# an upgrade, so a removal-only action without a guard runs on every
# upgrade too.

set -euo pipefail
cd "$(dirname "$0")/.."

PACKAGES=""
if [[ "${1-}" == "--packages" ]]; then
    PACKAGES="${2:?--packages needs a dist directory}"
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fails=0
fail() {
    echo "FAIL: $*" >&2
    fails=$((fails + 1))
}

# Stubs: each records "<name> <args>" to $STUB_LOG and succeeds. getent
# reports the group missing so postinstall's chgrp/chmod loop is skipped
# (it would otherwise act on a real /etc/parzival-broker).
mkdir -p "$work/bin" "$work/run-systemd"
for cmd in systemctl systemd-sysusers chgrp chmod; do
    # shellcheck disable=SC2016 # $* and $STUB_LOG expand when the stub runs
    printf '#!/bin/sh\necho "%s $*" >> "$STUB_LOG"\nexit 0\n' "$cmd" > "$work/bin/$cmd"
    chmod +x "$work/bin/$cmd"
done
printf '#!/bin/sh\nexit 2\n' > "$work/bin/getent"
chmod +x "$work/bin/getent"

# run <script> [args...] — runs a copy of the script with systemd "present",
# and prints the systemctl calls it made, one per line.
run() {
    local script="$1"
    shift
    local copy
    copy="$work/$(basename "$script")"
    sed "s#/run/systemd/system#$work/run-systemd#g" "$script" > "$copy"
    : > "$work/log"
    if ! STUB_LOG="$work/log" PATH="$work/bin:$PATH" sh "$copy" "$@" > /dev/null 2> "$work/stderr"; then
        fail "$script $* exited non-zero: $(cat "$work/stderr")"
    fi
    grep '^systemctl ' "$work/log" || true
}

disables_both() {
    grep -q '^systemctl disable --now parzival-broker.service$' <<< "$1" &&
        grep -q '^systemctl disable --now check-parzival-broker.timer$' <<< "$1"
}

# --- preremove.sh -------------------------------------------------------

# Removal: RPM erase (0), dpkg remove/deconfigure, and a bare run by hand.
for arg in 0 remove deconfigure ""; do
    out="$(run packaging/scripts/preremove.sh ${arg:+"$arg"})"
    disables_both "$out" || fail "preremove.sh '${arg}' (a removal) did not disable both units: ${out:-no systemctl calls}"
done

# Upgrade: RPM upgrade (1, or more with several installed instances), dpkg
# upgrade and failed-upgrade. Must not touch systemctl at all.
for args in "1" "2" "upgrade 0.3.0-1" "failed-upgrade 0.2.0-1"; do
    # shellcheck disable=SC2086 # deliberate word splitting into arguments
    out="$(run packaging/scripts/preremove.sh $args)"
    [[ -z "$out" ]] || fail "preremove.sh '$args' (an upgrade) called systemctl: $out"
done

# Without systemd running, a removal is a no-op too.
copy="$work/preremove-nosystemd.sh"
sed "s#/run/systemd/system#$work/does-not-exist#g" packaging/scripts/preremove.sh > "$copy"
: > "$work/log"
STUB_LOG="$work/log" PATH="$work/bin:$PATH" sh "$copy" 0 || fail "preremove.sh without systemd exited non-zero"
[[ ! -s "$work/log" ]] || fail "preremove.sh without systemd called: $(cat "$work/log")"

# --- postinstall.sh -----------------------------------------------------

# Fresh install: RPM 1, dpkg configure with no previous version. Reload
# only; the broker is never started, restarted, or enabled.
for args in "1" "configure" "configure "; do
    # shellcheck disable=SC2086
    out="$(run packaging/scripts/postinstall.sh $args)"
    [[ "$out" == "systemctl daemon-reload" ]] ||
        fail "postinstall.sh '$args' (a fresh install) made unexpected systemctl calls: ${out:-none}"
done

# Upgrade: RPM 2+, dpkg configure <previous-version>. Reload, then
# try-restart (which never starts a stopped broker) — in that order.
for args in "2" "3" "configure 0.2.0-1"; do
    # shellcheck disable=SC2086
    out="$(run packaging/scripts/postinstall.sh $args)"
    expected=$'systemctl daemon-reload\nsystemctl try-restart parzival-broker.service'
    [[ "$out" == "$expected" ]] ||
        fail "postinstall.sh '$args' (an upgrade) should reload then try-restart; got: ${out:-none}"
done

# dpkg unwinding a failed operation: reload only, no restart.
for args in "abort-upgrade 0.3.0-1" "abort-remove" "abort-deconfigure x"; do
    # shellcheck disable=SC2086
    out="$(run packaging/scripts/postinstall.sh $args)"
    [[ "$out" == "systemctl daemon-reload" ]] ||
        fail "postinstall.sh '$args' made unexpected systemctl calls: ${out:-none}"
done

# Nothing in postinstall may ever enable or plain-start the broker.
if grep -nE 'systemctl (enable|start|restart|reenable)( |$)' packaging/scripts/postinstall.sh; then
    fail "postinstall.sh must never enable, start, or unconditionally restart a unit"
fi

# --- postremove.sh ------------------------------------------------------

for args in "0" "1" "remove" "purge" "upgrade 0.3.0-1"; do
    # shellcheck disable=SC2086
    out="$(run packaging/scripts/postremove.sh $args)"
    [[ "$out" == "systemctl daemon-reload" ]] ||
        fail "postremove.sh '$args' made unexpected systemctl calls: ${out:-none}"
done

# --- built packages embed the scripts verbatim ---------------------------

if [[ -n "$PACKAGES" ]]; then
    shopt -s nullglob
    rpms=("$PACKAGES"/*.rpm)
    debs=("$PACKAGES"/*.deb)
    (( ${#rpms[@]} > 0 )) || fail "no .rpm files in $PACKAGES"
    (( ${#debs[@]} > 0 )) || fail "no .deb files in $PACKAGES"

    for pkg in "${debs[@]}"; do
        dir="$work/deb-$(basename "$pkg")"
        mkdir -p "$dir"
        dpkg-deb -e "$pkg" "$dir"
        for pair in prerm:preremove postinst:postinstall postrm:postremove; do
            cmp -s "$dir/${pair%%:*}" "packaging/scripts/${pair##*:}.sh" ||
                fail "$(basename "$pkg"): ${pair%%:*} is not packaging/scripts/${pair##*:}.sh verbatim"
        done
    done

    # rpm -qp --scripts prints each scriptlet as a header line followed by
    # the body; split them back out and compare each body to its source.
    for pkg in "${rpms[@]}"; do
        dir="$work/rpm-$(basename "$pkg")"
        mkdir -p "$dir"
        rpm -qp --scripts "$pkg" 2> /dev/null | awk -v dir="$dir" '
            /^[a-z]+ scriptlet \(using / { out = dir "/" $1; next }
            out { print > out }
        '
        for pair in preuninstall:preremove postinstall:postinstall postuninstall:postremove; do
            # rpm prints the body followed by one separating newline.
            if ! diff -q <(sed -e '$ { /^$/d; }' "$dir/${pair%%:*}" 2> /dev/null) \
                "packaging/scripts/${pair##*:}.sh" > /dev/null; then
                fail "$(basename "$pkg"): %${pair%%:*} is not packaging/scripts/${pair##*:}.sh verbatim"
            fi
        done
    done
fi

if (( fails > 0 )); then
    echo "test-package-scripts: $fails failure(s)" >&2
    exit 1
fi
echo "test-package-scripts: OK${PACKAGES:+ (including the scripts embedded in $PACKAGES)}"
