#!/usr/bin/env bash
#
# stage-release-assets.sh — build a clean, minimal staging directory
# containing exactly the artifacts a GitHub Release should carry, and
# nothing else GoReleaser happened to leave in dist/.
#
# This exists because GoReleaser's own dist/ is not a publishable set: it
# also holds metadata.json, the raw per-target build binaries (duplicates
# of the archived ones under a different name), and the rendered Homebrew
# cask — none of which belong as GitHub Release assets. It also holds two
# "Binary"-typed entries per target (the raw build output and the archived,
# publication-named output) with the same GoReleaser `type`, so filtering
# on type alone cannot tell them apart; this script filters on the
# artifact's declaring build/archive ID instead, read from
# dist/artifacts.json's own `extra.ID` field, matching this project's real
# .goreleaser.yml (builds: parzival, parzival-broker; archives:
# parzival-archive, parzival-broker-archive; nfpms: parzival-packages;
# sboms: parzival-sbom) rather than a name-pattern guess.
#
# The classification is intentionally closed, not permissive: any artifact
# whose type or ID this script does not recognize fails the run rather than
# being silently included or silently dropped. A .goreleaser.yml change
# that adds a new build, archive, or artifact class is exactly the kind of
# drift that should force a matching update here, not a surprise release
# asset (or a missing one).
#
# Usage: scripts/release/stage-release-assets.sh [dist-dir] [staging-dir]
#   dist-dir     defaults to "dist" (GoReleaser's own output directory,
#                already built and leak-scanned by the time this runs).
#   staging-dir  defaults to "dist/release-assets".
#
# On success, writes <staging-dir>/manifest.json — one entry per staged
# asset: {name, size, sha256} — for the publish step to verify against.
# manifest.json itself is never uploaded as a release asset.
#
# Exit 0: exactly the expected 16 assets staged (5 binaries, 4 packages,
# 5 SBOMs, 1 checksum file, 1 Sigstore signature bundle), each copied under
# its GoReleaser `name` as the staged filename. Exit 1 on the first problem
# category, after printing every instance in that category.

set -u
cd "$(dirname "$0")/../.." || exit 1

DIST="${1:-dist}"
STAGE="${2:-dist/release-assets}"
ARTIFACTS="$DIST/artifacts.json"

FAILURES=0
fail() {
    echo "stage-release-assets: FAIL: $1" >&2
    FAILURES=$((FAILURES + 1))
}
ok() {
    echo "stage-release-assets: ok: $1"
}

if [[ ! -f "$ARTIFACTS" ]]; then
    echo "stage-release-assets: $ARTIFACTS does not exist — did the GoReleaser build step run first?" >&2
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "stage-release-assets: jq is required and was not found on PATH" >&2
    exit 1
fi

# Known-good build/archive/package/sbom IDs from this project's real
# .goreleaser.yml. Anything of the relevant type with an ID outside this
# set is config drift this script does not understand yet, and fails
# closed rather than guessing.
RAW_BUILD_IDS='parzival parzival-broker'
ARCHIVE_IDS='parzival-archive parzival-broker-archive'

is_in() {
    local needle="$1" hay="$2" w
    for w in $hay; do [[ "$w" == "$needle" ]] && return 0; done
    return 1
}

rm -rf "$STAGE"
mkdir -p "$STAGE"

declare -A STAGED_NAMES=()
STAGED_COUNT=0
BINARY_COUNT=0
PACKAGE_RPM_COUNT=0
PACKAGE_DEB_COUNT=0
SBOM_COUNT=0
CHECKSUM_COUNT=0
SIGNATURE_COUNT=0

stage_one() {
    local name="$1" src="$2" class="$3"

    if [[ -n "${STAGED_NAMES[$name]:-}" ]]; then
        fail "duplicate staged name '$name' ($class) — already staged from '${STAGED_NAMES[$name]}', now also from '$src'"
        return
    fi

    if [[ ! -f "$src" ]]; then
        fail "$class artifact '$name' names a path that does not exist: $src"
        return
    fi

    cp -p "$src" "$STAGE/$name"
    STAGED_NAMES["$name"]="$src"
    STAGED_COUNT=$((STAGED_COUNT + 1))
}

# --- Binaries: only the archive-produced ones, never the raw build output ---
while IFS=$'\t' read -r name path id; do
    if is_in "$id" "$ARCHIVE_IDS"; then
        stage_one "$name" "$path" "binary"
        BINARY_COUNT=$((BINARY_COUNT + 1))
    elif is_in "$id" "$RAW_BUILD_IDS"; then
        : # raw per-target build binary — deliberately excluded, not an error
    else
        fail "Binary artifact '$name' has unrecognized build/archive ID '$id' — .goreleaser.yml's builds:/archives: changed without a matching update here"
    fi
done < <(jq -r '.[] | select(.type == "Binary") | [.name, .path, .extra.ID] | @tsv' "$ARTIFACTS")

# --- Linux packages: RPM + DEB ---
while IFS=$'\t' read -r name path format; do
    case "$format" in
        rpm) PACKAGE_RPM_COUNT=$((PACKAGE_RPM_COUNT + 1)) ;;
        deb) PACKAGE_DEB_COUNT=$((PACKAGE_DEB_COUNT + 1)) ;;
        *)
            fail "'Linux Package' artifact '$name' has unrecognized format '$format' (expected rpm or deb)"
            continue
            ;;
    esac
    stage_one "$name" "$path" "package"
done < <(jq -r '.[] | select(.type == "Linux Package") | [.name, .path, .extra.Format] | @tsv' "$ARTIFACTS")

# --- SBOMs ---
while IFS=$'\t' read -r name path; do
    stage_one "$name" "$path" "sbom"
    SBOM_COUNT=$((SBOM_COUNT + 1))
done < <(jq -r '.[] | select(.type == "SBOM") | [.name, .path] | @tsv' "$ARTIFACTS")

# --- Checksum file ---
while IFS=$'\t' read -r name path; do
    stage_one "$name" "$path" "checksum"
    CHECKSUM_COUNT=$((CHECKSUM_COUNT + 1))
done < <(jq -r '.[] | select(.type == "Checksum") | [.name, .path] | @tsv' "$ARTIFACTS")

# --- Signature (the keyless cosign Sigstore bundle over checksums.txt) ---
while IFS=$'\t' read -r name path; do
    stage_one "$name" "$path" "signature"
    SIGNATURE_COUNT=$((SIGNATURE_COUNT + 1))
done < <(jq -r '.[] | select(.type == "Signature") | [.name, .path] | @tsv' "$ARTIFACTS")

# --- Everything else: deliberately excluded classes, or unrecognized ones ---
while IFS=$'\t' read -r name type; do
    case "$type" in
        Metadata | "Homebrew Cask") ;; # not release assets — expected, not an error
        Binary | "Linux Package" | SBOM | Checksum | Signature) ;; # handled above
        *)
            fail "artifact '$name' has an unrecognized, unhandled type '$type' — this script's classification is deliberately closed; update it before releasing"
            ;;
    esac
done < <(jq -r '.[] | [.name, .type] | @tsv' "$ARTIFACTS")

if [[ "$BINARY_COUNT" -ne 5 ]]; then
    fail "expected 5 archive-produced binaries, staged $BINARY_COUNT"
else
    ok "staged $BINARY_COUNT binaries"
fi

if [[ "$PACKAGE_RPM_COUNT" -ne 2 || "$PACKAGE_DEB_COUNT" -ne 2 ]]; then
    fail "expected 2 RPM + 2 DEB packages, staged $PACKAGE_RPM_COUNT RPM + $PACKAGE_DEB_COUNT DEB"
else
    ok "staged $PACKAGE_RPM_COUNT RPM + $PACKAGE_DEB_COUNT DEB packages"
fi

if [[ "$SBOM_COUNT" -ne 5 ]]; then
    fail "expected 5 SBOMs, staged $SBOM_COUNT"
else
    ok "staged $SBOM_COUNT SBOMs"
fi

if [[ "$CHECKSUM_COUNT" -ne 1 ]]; then
    fail "expected exactly 1 checksum file, staged $CHECKSUM_COUNT"
else
    ok "staged $CHECKSUM_COUNT checksum file"
fi

if [[ "$SIGNATURE_COUNT" -ne 1 ]]; then
    fail "expected exactly 1 Sigstore signature bundle, staged $SIGNATURE_COUNT — was the build step's sign phase skipped?"
else
    ok "staged $SIGNATURE_COUNT Sigstore signature bundle"
fi

EXPECTED_TOTAL=16
if [[ "$STAGED_COUNT" -ne "$EXPECTED_TOTAL" ]]; then
    fail "expected exactly $EXPECTED_TOTAL total staged release assets, got $STAGED_COUNT"
else
    ok "staged $STAGED_COUNT total release assets"
fi

if [[ "$FAILURES" -gt 0 ]]; then
    echo "stage-release-assets: $FAILURES problem(s) found. Nothing published." >&2
    exit 1
fi

# Manifest for the publish step to verify against — never itself uploaded.
{
    echo "["
    first=1
    for name in "${!STAGED_NAMES[@]}"; do
        size=$(stat -c%s "$STAGE/$name")
        sha=$(sha256sum "$STAGE/$name" | cut -d' ' -f1)
        [[ "$first" -eq 1 ]] && first=0 || echo ","
        printf '  {"name": %s, "size": %s, "sha256": %s}' "$(jq -Rn --arg n "$name" '$n')" "$size" "$(jq -Rn --arg s "$sha" '$s')"
    done
    echo ""
    echo "]"
} > "$STAGE/manifest.json"

ok "wrote $STAGE/manifest.json"
ok "all checks passed."
