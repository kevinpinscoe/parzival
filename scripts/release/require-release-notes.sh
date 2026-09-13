#!/usr/bin/env bash
#
# require-release-notes.sh — fail the release CLOSED before GoReleaser ever
# runs, rather than let it fall back to an auto-generated changelog.
#
# GoReleaser's own `changelog:` machinery reads `git log` between tags, and
# this repository's real commit history routinely references internal
# ticket identifiers, host names, and private design rationale — fine in a
# commit message, not fine as public GitHub release-note text, even while
# the repo is private (a later publication audit has to treat everything
# sitting in GitHub Releases as publication-candidate content).
# `--release-notes release-notes.md` is what makes GoReleaser use
# hand-authored text instead; this script is what makes that mandatory
# rather than a convention someone can forget.
#
# Usage: scripts/release/require-release-notes.sh [path-to-release-notes.md]
#        (default: release-notes.md at the repo root)
#
# Exit 0: file exists, non-empty, passes the leakage sweep. Exit 1 otherwise,
# with a message naming exactly what failed — this is meant to be the first
# step of .github/workflows/release.yml, before any build happens.

set -u
cd "$(dirname "$0")/../.." || exit 1

NOTES="${1:-release-notes.md}"

fail() {
    echo "require-release-notes: FAIL: $1" >&2
    exit 1
}

if [[ ! -f "$NOTES" ]]; then
    fail "$NOTES does not exist. Write this release's notes before tagging. There is no fallback to an auto-generated changelog."
fi

if [[ ! -s "$NOTES" ]]; then
    fail "$NOTES exists but is empty. An empty file is not a hand-authored release note."
fi

# Same private-identifier sweep used across the project's public-surface
# reviews — see scripts/release/scan-release-artifacts.sh for the shared
# pattern list. Release notes get the identical treatment, not a lighter
# one, because they are the one release artifact a human wrote by hand and
# could paste something private into out of habit.
#
# Ticket-reference matching is case-SENSITIVE, kept in sync with
# scan-release-artifacts.sh's PRIVATE_PATTERN_TICKET: a real ticket
# reference is always written in caps ("PARZIVAL-NN"), and matching
# case-insensitively is what produced a real false positive there against
# auto-generated content elsewhere in the pipeline. Kept separate here too,
# even though hand-authored release notes are less likely to trip it, so
# the two scripts' behavior stays identical.
PRIVATE_PATTERN_CI='git\.kevininscoe\.com|kevininscoe\.com|openbao\.kevininscoe\.com|youtrack\.kevininscoe\.com|FLDW|kinscoe|/home/kinscoe'
PRIVATE_PATTERN_TICKET='PARZIVAL-[0-9]{1,4}[^.0-9]'

if grep -qEi "$PRIVATE_PATTERN_CI" "$NOTES" || grep -qE "$PRIVATE_PATTERN_TICKET" "$NOTES"; then
    echo "require-release-notes: FAIL: $NOTES contains what looks like a private identifier or internal ticket reference:" >&2
    { grep -nEi "$PRIVATE_PATTERN_CI" "$NOTES"; grep -nE "$PRIVATE_PATTERN_TICKET" "$NOTES"; } | sort -u >&2
    echo "Rewrite the offending line(s) for a public reader before releasing. There is no override." >&2
    exit 1
fi

echo "require-release-notes: OK: $NOTES is present, non-empty, and clean."
exit 0
