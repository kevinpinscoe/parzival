#!/usr/bin/env bash
#
# publish-github-release.sh — create (or safely resume) the GitHub Release
# for a tag as a DRAFT, upload exactly the staged assets, and verify the
# full inventory before returning success. Never publishes the draft
# itself — that is a separate, trivial `gh release edit --draft=false`
# step in .github/workflows/release.yml, run only after this script exits
# 0, so nothing downstream (Homebrew publication, RPM/APT dispatch) can
# run against a release that has not been verified.
#
# Retry-safe by design, because a release run can fail partway through
# after already creating a draft or uploading some assets:
#   - no release exists for the tag yet -> create it as a draft with every
#     staged asset attached in one `gh release create` call.
#   - a DRAFT already exists for the tag -> resume it: verify it targets
#     the expected commit, upload only the staged assets it is missing,
#     and refuse (fail closed) if an asset it already has conflicts in
#     size with the staged copy rather than silently re-uploading over it.
#   - a PUBLISHED release already exists for the tag and passes the exact
#     same artifact-integrity check as a freshly-verified draft (asset
#     count, names, every size, and digest where GitHub reports one) ->
#     this phase is already done; exit 0 without touching anything. A
#     published release with the right filenames but a replaced,
#     truncated, or corrupted asset does NOT pass this and is NOT treated
#     as done — see verify_asset_inventory(), used identically for both
#     the published-release retry path and the draft readback below, so
#     the two paths cannot drift apart.
#   - a PUBLISHED release exists that does NOT match expectations (wrong
#     target commit, wrong prerelease flag, or fails the integrity check
#     above) -> fail closed. This script never overwrites a conflicting
#     release; that needs a human.
#
# Usage: scripts/release/publish-github-release.sh <tag> [staging-dir] [release-notes.md]
#   tag           the exact tag this release is for (e.g. v0.1.0-pre.2).
#                 Must already exist in the remote — this script always
#                 passes --verify-tag and never lets `gh` synthesize one.
#   staging-dir   defaults to "dist/release-assets" — the output of
#                 stage-release-assets.sh, including its manifest.json.
#   release-notes.md  defaults to "release-notes.md" at the repo root.
#
# Exit 0 in either of two cases, both fully verified against
# staging-dir/manifest.json (exact asset count, exact names, every size,
# and digest where GitHub reports one) before returning: a DRAFT,
# prerelease, non-latest release for <tag> targeting the tag's own commit;
# or a PUBLISHED release for <tag> that already carries the identical
# asset set (the resume-on-retry no-op case). Exit 1 on the first problem
# found, in either case.

set -u
cd "$(dirname "$0")/../.." || exit 1

TAG="${1:?usage: publish-github-release.sh <tag> [staging-dir] [release-notes.md]}"
STAGE="${2:-dist/release-assets}"
NOTES="${3:-release-notes.md}"
MANIFEST="$STAGE/manifest.json"

fail() {
    echo "publish-github-release: FAIL: $1" >&2
    exit 1
}
ok() {
    echo "publish-github-release: ok: $1"
}

[[ -f "$MANIFEST" ]] || fail "$MANIFEST not found — run stage-release-assets.sh first"
command -v gh >/dev/null 2>&1 || fail "gh CLI not found"
command -v jq >/dev/null 2>&1 || fail "jq not found"

EXPECTED_COMMIT=$(git rev-parse "${TAG}^{commit}" 2>/dev/null) ||
    fail "tag '$TAG' does not resolve to a commit locally — was it fetched? (checkout needs fetch-depth: 0)"

EXPECTED_COUNT=$(jq 'length' "$MANIFEST")
EXPECTED_NAMES=$(jq -r '.[].name' "$MANIFEST" | sort)

release_view() {
    gh release view "$TAG" --json tagName,targetCommitish,isDraft,isPrerelease,assets,url 2>/dev/null
}

# A release object's targetCommitish is only meaningful as a cross-check
# when it looks like a real commit SHA — GitHub can report a branch name
# there in other circumstances, and this script's real source of truth for
# "the right commit" is the tag itself, resolved locally above.
check_target_commit() {
    local target="$1" context="$2"
    if [[ "$target" =~ ^[0-9a-f]{40}$ ]] && [[ "$target" != "$EXPECTED_COMMIT" ]]; then
        fail "$context release for $TAG targets commit $target, expected $EXPECTED_COMMIT (from the tag itself) — refusing to touch it"
    fi
}

# The one artifact-integrity check, used identically for a PUBLISHED
# release found on retry and for the draft this script just created or
# resumed: exact asset count, exact asset names, every asset's size
# nonzero and equal to the staged manifest, and — where GitHub reports a
# digest — an exact sha256 match. A published release does not get a
# lighter check just because its name and prerelease flag already looked
# right: a release with the right filenames but a replaced, truncated, or
# corrupted asset must fail here, not be waved through as "already done".
verify_asset_inventory() {
    local json="$1" context="$2"
    local count names digest_compared=0 digest_skipped=0

    count=$(jq '.assets | length' <<<"$json")
    [[ "$count" -eq "$EXPECTED_COUNT" ]] ||
        fail "$context release for $TAG: expected $EXPECTED_COUNT assets, found $count"

    names=$(jq -r '[.assets[].name] | sort | .[]' <<<"$json")
    [[ "$names" == "$EXPECTED_NAMES" ]] ||
        fail "$context release for $TAG: asset names do not exactly match the staged manifest"

    while IFS=$'\t' read -r name size sha; do
        local a_size a_digest
        a_size=$(jq -r --arg n "$name" '.assets[] | select(.name == $n) | .size' <<<"$json")
        [[ "$a_size" -gt 0 ]] || fail "$context release for $TAG: asset '$name' has zero size"
        [[ "$a_size" == "$size" ]] ||
            fail "$context release for $TAG: asset '$name' size $a_size != staged size $size"

        a_digest=$(jq -r --arg n "$name" '.assets[] | select(.name == $n) | (.digest // "")' <<<"$json")
        if [[ -n "$a_digest" ]]; then
            [[ "$a_digest" == "sha256:$sha" ]] ||
                fail "$context release for $TAG: asset '$name' digest $a_digest != staged sha256:$sha"
            digest_compared=$((digest_compared + 1))
        else
            digest_skipped=$((digest_skipped + 1))
        fi
    done < <(jq -r '.[] | [.name, .size, .sha256] | @tsv' "$MANIFEST")

    ok "$context release for $TAG: $count assets verified ($digest_compared digest(s) checked, $digest_skipped size-only)"
}

if EXISTING_JSON=$(release_view); then
    IS_DRAFT=$(jq -r '.isDraft' <<<"$EXISTING_JSON")
    IS_PRE=$(jq -r '.isPrerelease' <<<"$EXISTING_JSON")
    TARGET=$(jq -r '.targetCommitish' <<<"$EXISTING_JSON")
    URL=$(jq -r '.url' <<<"$EXISTING_JSON")

    check_target_commit "$TARGET" "existing"

    if [[ "$IS_DRAFT" == "false" ]]; then
        [[ "$IS_PRE" == "true" ]] || fail "existing PUBLISHED release for $TAG is not marked prerelease — conflicts with expectations ($URL)"
        verify_asset_inventory "$EXISTING_JSON" "existing PUBLISHED"
        ok "release for $TAG is already published with a fully verified asset set — nothing to do ($URL)"
        exit 0
    fi

    ok "found an existing DRAFT for $TAG targeting the expected commit — resuming it ($URL)"

    while IFS=$'\t' read -r name size; do
        have_size=$(jq -r --arg n "$name" '.assets[] | select(.name == $n) | .size' <<<"$EXISTING_JSON")
        if [[ -z "$have_size" ]]; then
            ok "uploading missing asset '$name' to the existing draft"
            gh release upload "$TAG" "$STAGE/$name" || fail "upload of '$name' failed"
        elif [[ "$have_size" != "$size" ]]; then
            fail "draft already has an asset named '$name' with size $have_size, staged copy is $size bytes — conflict, refusing to overwrite"
        fi
    done < <(jq -r '.[] | [.name, .size] | @tsv' "$MANIFEST")
else
    ok "no release exists yet for $TAG — creating it as a draft with all $EXPECTED_COUNT staged assets"
    mapfile -t FILES < <(jq -r '.[].name' "$MANIFEST" | sed "s|^|$STAGE/|")
    gh release create "$TAG" "${FILES[@]}" \
        --draft --prerelease --latest=false --verify-tag \
        --title "$TAG" --notes-file "$NOTES" ||
        fail "gh release create failed"
fi

# --- verify the full inventory before letting anything downstream run ---
FINAL_JSON=$(release_view) || fail "could not read back the release for $TAG after create/resume"

[[ "$(jq -r '.tagName' <<<"$FINAL_JSON")" == "$TAG" ]] || fail "readback tagName does not match $TAG"
[[ "$(jq -r '.isDraft' <<<"$FINAL_JSON")" == "true" ]] || fail "release for $TAG is not a draft — refusing to continue (publication happens in a later, separate step)"
[[ "$(jq -r '.isPrerelease' <<<"$FINAL_JSON")" == "true" ]] || fail "release for $TAG is not marked prerelease"
check_target_commit "$(jq -r '.targetCommitish' <<<"$FINAL_JSON")" "verified"
verify_asset_inventory "$FINAL_JSON" "draft"

DRAFT_URL=$(jq -r '.url' <<<"$FINAL_JSON")
ok "draft release for $TAG verified: target $EXPECTED_COMMIT, still a draft, marked prerelease, full asset inventory OK ($DRAFT_URL)"
