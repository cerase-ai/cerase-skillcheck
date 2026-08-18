#!/usr/bin/env bash
#
# Prune the GHCR container versions of ONE package, keeping the newest KEEP
# tagged ones and everything a protected tag rides on.
#
# Reads three variables from the environment and nothing else:
#   PACKAGE  the container package name, without the org prefix
#   KEEP     how many unprotected tagged versions survive
#   GH_TOKEN a token with packages:write, and Admin on the package to delete
# GITHUB_REPOSITORY_OWNER and GITHUB_REPOSITORY come from the runner.
#
# This calls the GHCR API directly instead of using
# actions/delete-package-versions, and the reason is a defect that was live in
# this workspace rather than a preference. That action tests its ignore-versions
# pattern against the version NAME, which for a container package is the
# manifest digest and never a tag — so a pattern naming latest, main and the
# release tags matched nothing, every version was a deletion candidate, and
# those tags survived only because they ride the newest digest while the action
# deletes oldest first. The runs were green and really did delete, so the
# protection had never been tested; a release tag older than the keep window
# would have gone silently. Here protection is read off the TAGS.
#
# The action also starts a whole batch at once and prints a counter incremented
# before the requests are sent, so its log reports as deleted what was only
# selected. Here the deletes are sequential, oldest first, each reported after
# the API has answered it.
#
# The check after the deletes is what keeps a pass meaningful: the selection is
# recomputed against the registry and must come back empty, so this cannot exit
# zero while the package still sits above its floor.
#
# cerase-core owns this file. Every repo with a retention workflow carries a
# byte-identical copy, written by `scripts/sync-tooling.sh` and pinned by
# `scripts/TOOLING.sha256`, which each retention workflow verifies before it
# runs this. Edit it here; never in a copy.

set -euo pipefail

: "${PACKAGE:?PACKAGE is required — the container package name}"
: "${KEEP:?KEEP is required — how many unprotected tagged versions survive}"
: "${GITHUB_REPOSITORY_OWNER:?GITHUB_REPOSITORY_OWNER is required — the org that owns the package}"

ORG="$GITHUB_REPOSITORY_OWNER"
ORG_PATH="/orgs/$ORG/packages/container/$PACKAGE"
USER_PATH="/users/$ORG/packages/container/$PACKAGE"
WORK="${RUNNER_TEMP:-/tmp}"
# Only ever compared against the package's linked repository, to explain a
# refusal. Outside a runner there is no such repository and the note is skipped.
RUNNING_IN="${GITHUB_REPOSITORY:-}"

# The status of the last failed gh call, read back out of its message because
# gh reports the code there and not in its exit status.
last_status() {
  sed -n 's/.*(HTTP \([0-9]\{3\}\)).*/\1/p' "$WORK/err" | tail -1
}

# The organization path is the documented one for a package an organization
# owns. It has been observed answering 503 for the versions collection while
# the user path returns the same list, so both are tried and the one that
# answered is used for every later call and printed. A retention run that
# quietly changed how it reads the registry is a run nobody can audit.
BASE=""
list_versions() {
  local out="$1" path attempt
  for path in "$ORG_PATH" "$USER_PATH"; do
    for attempt in 1 2 3; do
      if gh api "$path/versions?per_page=100" --paginate >"$WORK/raw" 2>"$WORK/err"; then
        jq -s 'add // []' "$WORK/raw" >"$out"
        BASE="$path"
        return 0
      fi
      case "$(last_status)" in
        429|5??) sleep $((attempt * 5)) ;;
        *) break ;;
      esac
    done
  done
  cat "$WORK/err" >&2
  return 1
}

delete_version() {
  local attempt
  for attempt in 1 2 3; do
    if gh api -X DELETE "$BASE/versions/$1" --silent >/dev/null 2>"$WORK/err"; then
      return 0
    fi
    case "$(last_status)" in
      429|5??) sleep $((attempt * 5)) ;;
      *) return 1 ;;
    esac
  done
  return 1
}

# Selection, and the whole point of writing it out rather than passing a
# pattern to an action: a version is protected by its TAGS. Untagged versions
# go first because these images are one platform with provenance off, so an
# untagged manifest is a superseded build and never a child of a tagged index.
cat >"$WORK/select.jq" <<'JQ'
[ .[]
  | { id, created_at, tags: (.metadata.container.tags // []) }
  | . + { protected: (.tags | any(. == "latest" or . == "main" or test("^v[0-9]"))) }
]
| ( map(select((.tags | length) == 0)) ) as $untagged
| ( map(select((.tags | length) > 0 and (.protected | not)))
    | sort_by(.created_at)
    | (if length > $keep then .[0 : length - $keep] else [] end) ) as $stale
| ($untagged + $stale)
| sort_by(.created_at)
| .[]
| "\(.id) \(.created_at) \(if (.tags|length) == 0 then "-" else (.tags|join(",")) end)"
JQ

list_versions "$WORK/versions.json" || {
  echo "::error::cannot read the versions of $PACKAGE"
  exit 1
}
echo "read $(jq length "$WORK/versions.json") versions of $PACKAGE via $BASE"

# Deleting a version needs the Admin role on the package; pushing to it needs
# only Write. A package stays linked to the repository that first published it,
# so a repo that took over the build can hold Write and nothing more.
LINKED="$(gh api "$ORG_PATH" --jq '.repository.full_name' 2>/dev/null || echo unknown)"
if [ -n "$RUNNING_IN" ] && [ "$LINKED" != "$RUNNING_IN" ]; then
  echo "note: $PACKAGE is linked to $LINKED while this workflow runs in $RUNNING_IN"
  echo "note: if a delete below is refused, the missing Admin grant on the package is why"
fi

jq -r --argjson keep "$KEEP" -f "$WORK/select.jq" \
  "$WORK/versions.json" >"$WORK/to-delete.txt"
SELECTED="$(wc -l <"$WORK/to-delete.txt" | tr -d ' ')"

jq -r '.[] | select((.metadata.container.tags // []) | any(. == "latest" or . == "main" or test("^v[0-9]")))
       | "kept, protected by tag: \(.id) \(.metadata.container.tags | join(","))"' \
  "$WORK/versions.json"

if [ "$SELECTED" -eq 0 ]; then
  echo "nothing to prune: every version is protected or inside the newest $KEEP"
  exit 0
fi
echo "selected $SELECTED versions to delete, oldest first"

DELETED=0
while read -r id created tags; do
  if delete_version "$id"; then
    DELETED=$((DELETED + 1))
    echo "deleted $id $created $tags"
    continue
  fi
  # GHCR answers a delete it will not allow and a delete of something already
  # gone with the same 404, and only one of the two may pass. Re-reading the
  # version separates them: the listing above proves this token can read the
  # package, so a version that reads back is one this token may not delete.
  if gh api "$BASE/versions/$id" >/dev/null 2>&1; then
    echo "::error::refused to delete version $id of $PACKAGE, which still exists."
    echo "::error::Deleting needs the Admin role on the package and this token appears to hold Write. Grant this repository Admin on the package in the organization package settings, run the retention from $LINKED, or supply a token carrying delete:packages."
    exit 1
  fi
  echo "version $id was already gone, skipped"
done <"$WORK/to-delete.txt"
echo "deleted $DELETED of $SELECTED selected versions"

# What makes a green run mean something. The selection is recomputed against
# the registry and must now be empty, so this cannot exit zero while the package
# still sits above its floor. The retries absorb the delay between a delete
# returning and the listing reflecting it; the count is printed either way.
LEFT=""
for attempt in 1 2 3; do
  sleep $((attempt * 5))
  list_versions "$WORK/after.json" || continue
  LEFT="$(jq -r --argjson keep "$KEEP" -f "$WORK/select.jq" "$WORK/after.json" | wc -l | tr -d ' ')"
  if [ "$LEFT" = "0" ]; then
    echo "$PACKAGE is at its floor: $(jq length "$WORK/after.json") versions remain"
    exit 0
  fi
done
echo "::error::the retention floor of $PACKAGE could not be confirmed after pruning (${LEFT:-the listing failed})"
exit 1
