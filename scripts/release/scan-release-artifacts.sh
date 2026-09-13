#!/usr/bin/env bash
#
# scan-release-artifacts.sh — the full source-information-leakage sweep over
# a GoReleaser build's output, run BETWEEN the build phase and the publish
# phase (see .github/workflows/release.yml's two-phase build/scan/publish
# split) so a leak fails the release before anything reaches GitHub, not
# after.
#
# Binaries are still public artifacts even while the source and the GitHub
# repo itself stay private (a later publication-readiness audit has to
# review everything that accumulated in GitHub Releases by then, so the
# same bar applies now, not only once the repo actually goes public).
#
# Usage: scripts/release/scan-release-artifacts.sh [--snapshot] <dist-dir> [release-notes.md]
#   --snapshot   verification mode: a missing release-notes.md is expected,
#                not a failure, since no release is being cut —
#                see the note above section 3 below. Every actual leak check
#                (binaries, packages, other artifacts, and release-notes.md
#                IF it happens to exist) runs identically to release mode;
#                --snapshot narrows only the one release-only prerequisite.
#   dist-dir defaults to "dist" (GoReleaser's default output directory).
#   release-notes.md defaults to release-notes.md at the repo root.
#
# Exit 0: nothing suspicious found in anything under dist-dir, or in
# release-notes.md. Exit 1 on the first category with a hit, after printing
# every hit in that category (not just the first) so one run tells you
# everything that needs fixing.

set -u
cd "$(dirname "$0")/../.." || exit 1

SNAPSHOT=0
if [[ "${1:-}" == "--snapshot" ]]; then
    SNAPSHOT=1
    shift
fi

DIST="${1:-dist}"
NOTES="${2:-release-notes.md}"

if [[ ! -d "$DIST" ]]; then
    echo "scan-release-artifacts: $DIST does not exist — nothing to scan (did the build step run first?)" >&2
    exit 1
fi

# Same pattern list used by require-release-notes.sh and this project's
# own public-surface reviews. Kept in sync manually — there
# being two copies is deliberate: require-release-notes.sh has to work
# standalone as the very first, cheapest gate, before a build exists to scan.
PRIVATE_PATTERN_CI='git\.kevininscoe\.com|kevininscoe\.com|openbao\.kevininscoe\.com|youtrack\.kevininscoe\.com|FLDW|kinscoe|/home/kinscoe|parzival-fldw'

# Case-SENSITIVE, deliberately: a real internal ticket reference is always
# written in caps ("PARZIVAL-NN") everywhere in this project. Running this
# pattern case-insensitively (as part of one combined -i pattern) failed on
# legitimate syft-generated SBOM content — SPDX identifiers embed the
# module's own public, lowercase
# name followed by a hash fragment (e.g. "SPDXRef-File-parzival-096ef9d5..."),
# which "parzival-[0-9]{1,4}[^.0-9]" matched purely by coincidence of digits
# following a hyphen, not because it named a ticket. Kept as its own pattern
# and matched case-sensitively so a real "PARZIVAL-NN" reference is still
# always caught, while the module's own lowercase name in generated
# identifiers no longer is.
PRIVATE_PATTERN_TICKET='PARZIVAL-[0-9]{1,4}[^.0-9]'

FAILURES=0
fail() {
    echo "scan-release-artifacts: FAIL: $1" >&2
    FAILURES=$((FAILURES + 1))
}
ok() {
    echo "scan-release-artifacts: ok: $1"
}

# Both helpers read exactly one candidate text from stdin (a file, a
# here-string, or a pipe) and apply the same two-pattern rule everywhere in
# this script: -i for genuine private identifiers/hosts, case-sensitive for
# the ticket-reference shape (see the comment on PRIVATE_PATTERN_TICKET
# above for why the split exists). -a treats binary input as text so the
# same helper is safe to use for both binaries and plain text.
matches_private_pattern() {
    local text
    text="$(cat)"
    grep -qaEi "$PRIVATE_PATTERN_CI" <<<"$text" && return 0
    grep -qaE "$PRIVATE_PATTERN_TICKET" <<<"$text"
}
grep_private_pattern() {
    local text
    text="$(cat)"
    {
        grep -aEi "$PRIVATE_PATTERN_CI" <<<"$text"
        grep -aE "$PRIVATE_PATTERN_TICKET" <<<"$text"
    } | sort -u
}

# --- 1. Binaries: go version -m + targeted strings, per architecture -------
# Conditional compilation (mount_linux.go vs mount_darwin.go, etc.) could in
# principle embed different strings per platform, so every built binary is
# checked individually rather than sampling one.
binary_count=0
while IFS= read -r -d '' bin; do
    binary_count=$((binary_count + 1))
    label="${bin#"$DIST"/}"

    # go version -m confirms embedded module path / VCS info is only ever a
    # commit hash + timestamp, never a local filesystem path (which -trimpath
    # in .goreleaser.yml's builds: flags: is what actually prevents).
    if ! go version -m "$bin" >/dev/null 2>&1; then
        fail "$label: 'go version -m' could not read this binary at all"
        continue
    fi
    if go version -m "$bin" 2>/dev/null | grep -qE '/home/[a-z]+|/(Users|home)/[a-zA-Z0-9_.-]+/(Projects|go/src)'; then
        fail "$label: 'go version -m' shows a local filesystem build path — -trimpath did not take effect"
    fi

    if strings "$bin" 2>/dev/null | matches_private_pattern; then
        fail "$label: strings sweep found a private identifier or internal ticket reference"
        strings "$bin" 2>/dev/null | grep_private_pattern >&2
    fi
done < <(find "$DIST" -type f -perm -u+x -print0 2>/dev/null)
[[ "$binary_count" -gt 0 ]] && ok "swept $binary_count binary/binaries"

# --- 2a. .rpm / .deb packages: extracted contents + metadata, not raw bytes -
# A real finding: grepping a compressed .rpm/.deb file's raw
# bytes directly produces both false positives (compressed payload noise
# coincidentally matching the pattern) and would produce false negatives
# too (a real match split across a compression boundary). Package metadata
# (Packager/Buildhost/Description/URL) and scriptlets (postinstall/preremove/
# postremove) are genuinely new text not already covered by the binary sweep
# above; everything else inside the package is a copy of a file already
# checked at the source-tree/binary level — still re-extracted and swept
# here for defense in depth, not trusted merely because it was clean before
# packaging.
scan_pkg_text() {
    local label="$1" text="$2"
    if matches_private_pattern <<<"$text"; then
        fail "$label: contains a private identifier or internal ticket reference"
        grep_private_pattern <<<"$text" >&2
    fi
}

pkg_count=0
while IFS= read -r -d '' pkg; do
    pkg_count=$((pkg_count + 1))
    label="${pkg#"$DIST"/}"
    extract_dir="$(mktemp -d)"

    case "$pkg" in
    *.rpm)
        scan_pkg_text "$label (rpm metadata)" "$(rpm -qip "$pkg" 2>&1)"
        scan_pkg_text "$label (rpm scriptlets)" "$(rpm -qp --scripts "$pkg" 2>&1)"
        (cd "$extract_dir" && rpm2cpio "$OLDPWD/$pkg" | cpio -idm --quiet 2>/dev/null)
        ;;
    *.deb)
        scan_pkg_text "$label (deb control)" "$(dpkg-deb -I "$pkg" 2>&1)"
        dpkg-deb -e "$pkg" "$extract_dir/DEBIAN" 2>/dev/null
        scan_pkg_text "$label (deb maintainer scripts)" "$(cat "$extract_dir"/DEBIAN/{preinst,postinst,prerm,postrm} 2>/dev/null)"
        dpkg-deb -x "$pkg" "$extract_dir" 2>/dev/null
        ;;
    *)
        rm -rf "$extract_dir"
        continue
        ;;
    esac

    # Sweep the extracted file tree with the same binary/text logic as
    # sections 1/2b, not a separate weaker check.
    while IFS= read -r -d '' ef; do
        [[ -f "$ef" ]] || continue
        elabel="$label -> ${ef#"$extract_dir"/}"
        if [[ -x "$ef" ]] && file "$ef" 2>/dev/null | grep -qi 'executable'; then
            if go version -m "$ef" >/dev/null 2>&1; then
                if go version -m "$ef" 2>/dev/null | grep -qE '/home/[a-z]+|/(Users|home)/[a-zA-Z0-9_.-]+/(Projects|go/src)'; then
                    fail "$elabel: 'go version -m' shows a local filesystem build path"
                fi
            fi
            if strings "$ef" 2>/dev/null | matches_private_pattern; then
                fail "$elabel: strings sweep found a private identifier or internal ticket reference"
                strings "$ef" 2>/dev/null | grep_private_pattern >&2
            fi
        else
            if matches_private_pattern <"$ef" 2>/dev/null; then
                fail "$elabel: contains a private identifier or internal ticket reference"
                grep_private_pattern <"$ef" 2>/dev/null >&2
            fi
        fi
    done < <(find "$extract_dir" -type f -print0 2>/dev/null)

    rm -rf "$extract_dir"
done < <(find "$DIST" -type f \( -name '*.rpm' -o -name '*.deb' \) -print0 2>/dev/null)
[[ "$pkg_count" -gt 0 ]] && ok "swept $pkg_count package(s) (extracted contents + metadata, not raw bytes)"

# --- 2b. Everything else: checksums, signatures, SBOMs, archives -----------
# Plain text/binary files GoReleaser produced that aren't .rpm/.deb (handled
# specially above, since raw-grepping a compressed package file is
# unreliable) and aren't the executables already swept in section 1.
other_count=0
while IFS= read -r -d '' f; do
    [[ -f "$f" ]] || continue
    case "$f" in *.rpm | *.deb) continue ;; esac
    if [[ -x "$f" ]] && file "$f" 2>/dev/null | grep -qi 'executable'; then
        continue
    fi
    other_count=$((other_count + 1))
    label="${f#"$DIST"/}"
    if matches_private_pattern <"$f" 2>/dev/null; then
        fail "$label: contains a private identifier or internal ticket reference"
        grep_private_pattern <"$f" 2>/dev/null >&2
    fi
done < <(find "$DIST" -type f -print0 2>/dev/null)
[[ "$other_count" -gt 0 ]] && ok "swept $other_count non-binary, non-package artifact(s) (checksums/signatures/SBOMs/archives)"

# --- 3. release-notes.md itself ----------------------------------------------
# require-release-notes.sh already checked this before the build ran; this
# repeats the check against the exact file being published, in case anything
# touched it in between (defense in depth, not distrust of that script).
#
# A missing file is a real release-gate failure in release mode (the
# GitHub Actions verification workflow never reaches this branch: --snapshot
# is passed on every invocation from that workflow, since a snapshot run
# never cuts a release and therefore never has a release-notes.md to check).
# In --snapshot mode a missing file is expected, not a leak and not a release
# defect — this is the one release-only prerequisite --snapshot narrows; if
# the file happens to exist anyway, it is still scanned exactly as in release
# mode, since existing content can leak regardless of which mode is running.
if [[ -f "$NOTES" ]]; then
    if matches_private_pattern <"$NOTES"; then
        fail "$NOTES: contains a private identifier or internal ticket reference"
        grep_private_pattern <"$NOTES" >&2
    else
        ok "$NOTES clean"
    fi
elif [[ "$SNAPSHOT" -eq 1 ]]; then
    ok "$NOTES not present — expected in --snapshot mode, no release is being cut"
else
    fail "$NOTES is missing at scan time (require-release-notes.sh should have caught this earlier)"
fi

if [[ "$FAILURES" -gt 0 ]]; then
    echo "scan-release-artifacts: $FAILURES check(s) failed. Refusing to publish." >&2
    exit 1
fi

echo "scan-release-artifacts: all checks passed."
exit 0
