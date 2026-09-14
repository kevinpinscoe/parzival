#!/usr/bin/env bash
#
# publish-homebrew-cask.sh — push the already-built, already-leak-scanned
# Homebrew cask to kevinpinscoe/homebrew-tap via the GitHub Contents API,
# using whatever token `gh` is authenticated with in the environment (the
# workflow sets that to the dedicated HOMEBREW_TAP_TOKEN via the step's
# own `env:` block — this script never reads or references the token by
# name, so its value never appears in anything this script prints).
#
# Does not regenerate the cask: it publishes exactly the file GoReleaser
# rendered and scripts/release/scan-release-artifacts.sh already scanned,
# byte for byte.
#
# Idempotent by design, because a release run can fail after this step's
# public side effect already landed:
#   - the tap's copy is byte-identical to the local cask -> success/no-op.
#   - the tap has no file at that path yet -> create it.
#   - the tap has a different file there -> update it, using the blob's
#     current sha (required by the Contents API for an update, and doubles
#     as an optimistic-concurrency check against a concurrent writer).
# After any create/update, the tap is read back and the result is required
# to match the local file exactly before this script reports success.
#
# Usage: scripts/release/publish-homebrew-cask.sh [cask-file] [target-repo] [target-path] [branch]
#   cask-file    defaults to "dist/homebrew/Casks/parzival.rb"
#   target-repo  defaults to "kevinpinscoe/homebrew-tap"
#   target-path  defaults to "Casks/parzival.rb"
#   branch       defaults to "main"
#
# Exit 0: the tap's Casks/parzival.rb is confirmed byte-identical to the
# local cask file. Exit 1 on any GitHub API failure or verification
# mismatch — never leaves this "maybe updated, maybe not" without saying
# so on stderr.

set -u
cd "$(dirname "$0")/../.." || exit 1

CASK_FILE="${1:-dist/homebrew/Casks/parzival.rb}"
TARGET_REPO="${2:-kevinpinscoe/homebrew-tap}"
TARGET_PATH="${3:-Casks/parzival.rb}"
BRANCH="${4:-main}"

fail() {
    echo "publish-homebrew-cask: FAIL: $1" >&2
    exit 1
}
ok() {
    echo "publish-homebrew-cask: ok: $1"
}

[[ -f "$CASK_FILE" ]] || fail "$CASK_FILE not found — did the GoReleaser build step run?"
command -v gh >/dev/null 2>&1 || fail "gh CLI not found"
command -v jq >/dev/null 2>&1 || fail "jq not found"

LOCAL_SHA256=$(sha256sum "$CASK_FILE" | cut -d' ' -f1)
LOCAL_B64=$(base64 -w0 "$CASK_FILE")

remote_content_sha256() {
    # Reads $1 (a GitHub Contents API JSON response) and prints the
    # sha256 of its decoded file content.
    jq -r '.content' <<<"$1" | base64 -d | sha256sum | cut -d' ' -f1
}

GET_ERR=$(mktemp)
EXISTING_JSON=$(gh api "repos/$TARGET_REPO/contents/$TARGET_PATH?ref=$BRANCH" 2>"$GET_ERR")
GET_STATUS=$?
GET_ERR_TEXT=$(cat "$GET_ERR")
rm -f "$GET_ERR"

if [[ "$GET_STATUS" -eq 0 ]]; then
    EXISTING_SHA=$(jq -r '.sha' <<<"$EXISTING_JSON")
    EXISTING_CONTENT_SHA256=$(remote_content_sha256 "$EXISTING_JSON")

    if [[ "$EXISTING_CONTENT_SHA256" == "$LOCAL_SHA256" ]]; then
        ok "$TARGET_REPO:$TARGET_PATH already matches the local cask exactly (blob $EXISTING_SHA) — nothing to publish"
        exit 0
    fi

    ok "$TARGET_REPO:$TARGET_PATH exists but differs — updating blob $EXISTING_SHA"
    PUT_ARGS=(-f "sha=$EXISTING_SHA")
elif [[ "$GET_ERR_TEXT" == *"404"* || "$GET_ERR_TEXT" == *"Not Found"* ]]; then
    ok "$TARGET_REPO:$TARGET_PATH does not exist yet — creating it"
    PUT_ARGS=()
else
    fail "could not read $TARGET_REPO:$TARGET_PATH: $GET_ERR_TEXT"
fi

COMMIT_MESSAGE="release: update parzival cask"
if ! gh api "repos/$TARGET_REPO/contents/$TARGET_PATH" \
    --method PUT \
    -f "message=$COMMIT_MESSAGE" \
    -f "content=$LOCAL_B64" \
    -f "branch=$BRANCH" \
    "${PUT_ARGS[@]}" >/dev/null; then
    fail "PUT to $TARGET_REPO:$TARGET_PATH failed"
fi

VERIFY_JSON=$(gh api "repos/$TARGET_REPO/contents/$TARGET_PATH?ref=$BRANCH" 2>&1) ||
    fail "could not read back $TARGET_REPO:$TARGET_PATH after publishing"

VERIFY_SHA256=$(remote_content_sha256 "$VERIFY_JSON")
[[ "$VERIFY_SHA256" == "$LOCAL_SHA256" ]] ||
    fail "$TARGET_REPO:$TARGET_PATH does not match the local cask after publishing (repo sha256 $VERIFY_SHA256, local $LOCAL_SHA256)"

ok "$TARGET_REPO:$TARGET_PATH verified byte-identical to the local cask after publishing"
