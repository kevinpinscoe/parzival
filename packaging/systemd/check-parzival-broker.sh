#!/usr/bin/env bash
# check-parzival-broker — assert that parzival-broker is actually answering
# real tea.repos-list requests, not just that the unit is `active`.
#
# The failure this exists to catch is silent in the same way check-ydotool's
# is: `systemctl is-active` proves the process exists, not that it can still
# reach OpenBao or Gitea, or that its trust-root verification didn't leave it
# refusing every request. Only a real request through the socket proves the
# work product.
#
# Documentation: https://github.com/kevinpinscoe/parzival
#
# NOTE on scope (deliberate): this script implements the health-check +
# deadman + silent-fail detections via one real functional request. It does
# NOT implement an audit-log error-rate check for "the broker is up but
# failing many other requests" — the audit log is intentionally 0600, owned
# by the parzival-broker service account, unreadable by any other user, and
# it should stay that way; a packaging-side change is not the place to
# weaken a secrets project's own audit-log permissions to make a checker's
# job easier. That detection is deferred pending a decision on how to
# expose it safely (a narrow sudo rule for a read-only check, or a future
# non-sensitive summary operation the broker itself serves over its socket).
#
# NOTE on alerting: this script is the generic, public half of the health
# check. It signals health entirely through its exit status (0 = healthy,
# 1 = a check failed) and through ordinary journald-visible logging — it
# contains no dependency on any specific push-monitor or chat-alert
# infrastructure. A site that wants one wires this script's exit status
# into its own monitoring at the host level (a systemd drop-in, an
# OnFailure= unit, a wrapper) rather than this script calling out to one
# directly.

set -uo pipefail

# --- Paths -------------------------------------------------------------------
# Absolutely qualified: this runs under systemd's minimal PATH.
SYSTEMCTL=/usr/bin/systemctl
HOSTNAME_BIN=/usr/bin/hostname
PARZIVAL=/usr/bin/parzival

DEFAULT_SOCKET=/run/parzival/broker.sock
DEFAULT_UNIT=parzival-broker.service
SOCKET="${SOCKET:-$DEFAULT_SOCKET}"
UNIT="${UNIT:-$DEFAULT_UNIT}"

# OWNER has no default: it names the real Gitea account/org this install's
# tea.repos-list consumer definition is configured for (examples/consumers/
# tea.json), which is genuinely site-specific — there is no generic value
# that would exercise a real request on every install. Set it in
# /etc/parzival-broker/environment (see packaging/README.md); the unit
# refuses to run meaningfully without it rather than silently checking
# against someone else's account name.
if [[ -z "${OWNER:-}" ]]; then
    echo "check-parzival-broker: \$OWNER is not set — see packaging/README.md" >&2
    exit 1
fi

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

FAILURES=()
fail() { FAILURES+=("$1"); log "FAIL: $1"; }
pass() { log "ok: $1"; }

# 1. Deadman, the "it was never going to run" half.
enabled_state=$("$SYSTEMCTL" is-enabled "$UNIT" 2>&1)
case "$enabled_state" in
    enabled|enabled-runtime) pass "$UNIT is ${enabled_state}" ;;
    masked|masked-runtime)   fail "$UNIT is MASKED — it cannot start at all" ;;
    *)                       fail "$UNIT is not enabled (systemctl is-enabled: ${enabled_state})" ;;
esac

# 2. Health, part one: the unit is actually running now.
active_state=$("$SYSTEMCTL" is-active "$UNIT" 2>&1)
if [[ "$active_state" == "active" ]]; then
    pass "$UNIT is active"
else
    fail "$UNIT is not active (systemctl is-active: ${active_state})"
fi

# 3. Health, part two, and the real one: a live request through the socket,
#    exercising authorization, the OpenBao fetch, the launcher, and response
#    canonicalization end to end. This is what would have caught the broker
#    being "active" but unable to reach OpenBao, or refusing every request
#    because its trust-root verification left it in a bad state.
if result=$("$PARZIVAL" service --socket "$SOCKET" --input "owner=${OWNER}" tea.repos-list 2>&1); then
    pass "tea.repos-list --input owner=${OWNER} returned a canonical result"
else
    fail "tea.repos-list --input owner=${OWNER} failed: ${result}"
fi

# --- Verdict -----------------------------------------------------------------
# Signalled entirely through exit status and journald-visible logging (see
# the "NOTE on alerting" header comment) — no push-monitor beat, no chat
# alert. A site wires this into its own monitoring at the host level.
if (( ${#FAILURES[@]} == 0 )); then
    log "All checks passed."
    exit 0
fi

host=$("$HOSTNAME_BIN" -s)
log "${#FAILURES[@]} check(s) failed on ${host}:"
for f in "${FAILURES[@]}"; do
    log "  - ${f}"
done
log "Diagnose: systemctl status parzival-broker --no-pager; journalctl -u parzival-broker -n 50"

exit 1
