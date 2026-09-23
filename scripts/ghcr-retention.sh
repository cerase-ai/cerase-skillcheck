#!/usr/bin/env bash
#
# Prune the GHCR container versions of ONE package, keeping the newest KEEP
# tagged ones and everything a protected tag rides on.
#
# Usage: ghcr-retention.sh [--dry-run]
#
# Reads these variables from the environment and nothing else:
#   PACKAGE          the container package name, without the org prefix
#   KEEP             how many unprotected tagged versions survive
#   GH_TOKEN         a token with packages:write, and Admin on the package to delete
#   RELEASE_TAGS_URL where the Fleet Console lists the tags its releases pin,
#                    defaulting to the console's own address
#   GHCR_RETENTION_DRY_RUN
#                    1 or true for a dry run, the form a workflow input sets;
#                    empty, 0 or false for a real one
# GITHUB_REPOSITORY_OWNER and GITHUB_REPOSITORY come from the runner.
#
# A dry run makes every read a real run makes before its first delete, stops
# where a real run stops when the release list cannot be read, prints the same
# plan with a reason for every version, and exits before the first delete. A
# read-only token is enough for it. A mode this script does not recognise, from
# either the flag or the variable, is refused before anything is read: a
# mistyped request for a dry run must not prune.
#
# A tag a release pins is protected like latest and main. The newest KEEP tagged
# versions are a few days of history for an image that gains one on most
# pushes, and a release is cut, tried on the canary and the early ring, and
# promoted days later; a rollback promotes one from the week before. Pruned by
# age, its tags are gone by the time a box is told to pull them. The console
# holds the releases and publishes those tags, so reading them needs no
# credential. An answer that cannot be read stops the run before a single
# version is listed: pruning as if no release pinned anything is the one
# outcome worse than not pruning.
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

DRY_RUN=""
case "${GHCR_RETENTION_DRY_RUN:-}" in
  ""|0|false) ;;
  1|true) DRY_RUN=1 ;;
  *)
    echo "::error::GHCR_RETENTION_DRY_RUN is '$GHCR_RETENTION_DRY_RUN'; it takes 1 or true for a dry run, and empty, 0 or false for a real one, so nothing is read or deleted"
    exit 2
    ;;
esac
case "$#:${1:-}" in
  0:) ;;
  1:--dry-run) DRY_RUN=1 ;;
  *)
    echo "::error::usage: ghcr-retention.sh [--dry-run]; nothing is read or deleted"
    exit 2
    ;;
esac

: "${PACKAGE:?PACKAGE is required — the container package name}"
: "${KEEP:?KEEP is required — how many unprotected tagged versions survive}"
: "${GITHUB_REPOSITORY_OWNER:?GITHUB_REPOSITORY_OWNER is required — the org that owns the package}"

ORG="$GITHUB_REPOSITORY_OWNER"
RELEASE_TAGS_URL="${RELEASE_TAGS_URL:-https://dash.cerase.ai/api/v1/releases/tags}"
ORG_PATH="/orgs/$ORG/packages/container/$PACKAGE"
USER_PATH="/users/$ORG/packages/container/$PACKAGE"
WORK="${RUNNER_TEMP:-/tmp}"
# The repository this run is in, compared against the package's linked
# repository and named in what a dry run says a real prune needs. Outside a
# runner there is none, and neither the note nor the name is printed.
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

# The tags the console's releases pin for this package, as a JSON array.
#
# The shape is checked whole before any of it is used: an object under `images`
# whose every value is a list of sha tags. A maintenance page, a proxy's error
# body, or a list keyed by something else is an answer this run cannot read,
# and it says so instead of treating it as a list with nothing in it. curl's own
# retry covers the transient failures a console restart produces.
read_release_tags() {
  local out="$1"
  if ! curl -fsS --retry 2 --retry-delay 5 --max-time 20 -H 'Accept: application/json' \
      "$RELEASE_TAGS_URL" >"$WORK/release-tags.json" 2>"$WORK/err"; then
    cat "$WORK/err" >&2
    return 1
  fi
  jq -e '
    (.images | type == "object")
    and ([.images[] | type == "array"] | all)
    and ([.images[][] | type == "string" and test("^sha-[0-9a-f]{7,40}$")] | all)
  ' "$WORK/release-tags.json" >/dev/null 2>&1 || {
    echo "the answer is not a map of images to lists of sha tags" >&2
    return 1
  }
  jq -c --arg package "$PACKAGE" '.images[$package] // []' "$WORK/release-tags.json" >"$out"
}

# The plan, and the whole point of writing it out rather than passing a pattern
# to an action: a version is protected by its TAGS. Every version gets an action
# and the one reason that decided it, oldest first. A tag latest, main or v*
# protects before a release pin does, so the versions counted as pinned by a
# release are the ones only the console's list keeps. Untagged versions are
# deleted because these images are one platform with provenance off, so an
# untagged manifest is a superseded build and never a child of a tagged index.
cat >"$WORK/plan.jq" <<'JQ'
[ .[]
  | { id, name, created_at, tags: (.metadata.container.tags // []) }
  | . + { by_tag: (.tags | any(. == "latest" or . == "main" or test("^v[0-9]"))),
          by_release: (.tags | any(. as $tag | $pinned | index([$tag]) != null)) }
]
| ( map(select((.tags | length) > 0 and (.by_tag | not) and (.by_release | not)))
    | sort_by(.created_at)
    | (if length > $keep then [.[0 : length - $keep][] | .id] else [] end) ) as $stale
| map(. + (if (.tags | length) == 0 then {action: "delete", reason: "untagged"}
           elif .by_tag then {action: "keep", reason: "protected by tag"}
           elif .by_release then {action: "keep", reason: "pinned by a release"}
           elif (.id as $id | $stale | index([$id]) != null) then {action: "delete", reason: "older than the newest \($keep)"}
           else {action: "keep", reason: "inside the newest \($keep)"} end)
       | del(.by_tag, .by_release))
| sort_by(.created_at)
JQ

plan() {   # <versions.json> <plan.json>
  jq --argjson keep "$KEEP" --argjson pinned "$PINNED" -f "$WORK/plan.jq" "$1" >"$2"
  keep_referenced "$2"
}

# An untagged version is not always garbage. An attested or multi-arch image is
# an index, and the manifests it lists are package versions with no tag of
# their own: deleting "untagged" deleted the inside of every such image, and
# left both meeting-bot packages with tags — `latest` among them —
# whose index answered 200 and whose manifests answered 404. So every tagged
# version this run keeps has its manifest read, and what an index lists is kept.
#
# A manifest that cannot be read deletes no untagged version at all: whether it
# lists one is exactly what is unknown, and a prune that guesses is the defect.
ACCEPT_MANIFESTS='application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json'

registry_token() {
  printf 'user = "x:%s"\n' "${GH_TOKEN:-${GITHUB_TOKEN:-}}" \
    | curl -fsS --max-time 20 -K - "https://ghcr.io/token?scope=repository:$ORG/$PACKAGE:pull" 2>"$WORK/err" \
    | jq -r '.token // empty'
}

keep_referenced() {   # <plan.json>
  local file="$1" token="" name unreadable=""
  [ "$(jq '[.[] | select(.action == "delete" and (.tags | length) == 0)] | length' "$file")" -gt 0 ] || return 0

  # Every tagged version kept, by digest. None kept means nothing can list one.
  jq -r '.[] | select(.action == "keep" and (.tags | length) > 0) | .name // "-"' "$file" >"$WORK/kept-names"
  : >"$WORK/referenced"
  if [ -s "$WORK/kept-names" ]; then
    token="$(registry_token)"
    [ -n "$token" ] || unreadable="the registry token"
    while [ -z "$unreadable" ] && read -r name; do
      if [ "$name" = "-" ]; then
        unreadable="a kept version with no digest"
      elif ! printf 'header = "Authorization: Bearer %s"\n' "$token" \
          | curl -fsS --max-time 20 -K - -H "Accept: $ACCEPT_MANIFESTS" \
            "https://ghcr.io/v2/$ORG/$PACKAGE/manifests/$name" >"$WORK/manifest.json" 2>"$WORK/err" \
          || ! jq -r '.manifests[]?.digest' "$WORK/manifest.json" >>"$WORK/referenced" 2>/dev/null; then
        unreadable="the manifest $name"
      fi
    done <"$WORK/kept-names"
  fi

  if [ -n "$unreadable" ]; then
    echo "::warning::$unreadable of $PACKAGE could not be read, so no untagged version is deleted this run"
    jq --arg why "the registry could not say what a kept index lists" \
      'map(if .action == "delete" and (.tags | length) == 0 then .action = "keep" | .reason = $why else . end)' \
      "$file" >"$file.tmp" && mv "$file.tmp" "$file"
    return 0
  fi

  jq --slurpfile refs <(jq -R . "$WORK/referenced" | jq -s .) \
    'map(if .action == "delete" and (.tags | length) == 0 and (.name as $n | $refs[0] | index($n)) != null
         then .action = "keep" | .reason = "referenced by a kept index" else . end)' \
    "$file" >"$file.tmp" && mv "$file.tmp" "$file"
}

# How many versions of a plan carry an action, and a reason when one is given.
count() {   # <plan.json> <action> [<reason>]
  jq --arg action "$2" --arg reason "${3:-}" \
    '[.[] | select(.action == $action and ($reason == "" or .reason == $reason))] | length' "$1"
}

read_release_tags "$WORK/pinned.json" || {
  echo "::error::cannot read the tags live releases pin from $RELEASE_TAGS_URL, so nothing of $PACKAGE is deleted"
  exit 1
}
PINNED="$(cat "$WORK/pinned.json")"
echo "live releases pin $(jq length "$WORK/pinned.json") tag(s) of $PACKAGE, read from $RELEASE_TAGS_URL"

list_versions "$WORK/versions.json" || {
  echo "::error::cannot read the versions of $PACKAGE"
  exit 1
}
echo "read $(jq length "$WORK/versions.json") versions of $PACKAGE via $BASE"

# Deleting a version needs the Admin role on the package; pushing to it needs
# only Write. A package stays linked to the repository that first published it,
# so a repo that took over the build can hold Write and nothing more.
#
# LINKED is the repository the package answer names, and empty when it names
# none. A workflow token's answer carries no `repository` object, whether that
# token can write packages or not and whichever repository the package is linked
# to, and jq then prints nothing while gh still exits 0. Empty therefore means
# unknown, never another repository: every message below says what the answer
# named, and a real run explains a refused delete only when one is refused.
#
# A dry run makes no delete and cannot read who holds that role, so it states
# what a real prune needs, the role and the linked repository, as facts to check
# in the package's settings, and nothing about a delete being refused.
LINKED="$(gh api "$ORG_PATH" --jq '.repository.full_name // empty' 2>/dev/null || true)"
if [ -n "$DRY_RUN" ]; then
  if [ -n "$LINKED" ]; then
    link="the package is linked to $LINKED"
  else
    link="the repository the package is linked to cannot be read with this token"
  fi
  echo "a real prune${RUNNING_IN:+ from $RUNNING_IN} needs the admin role on the $PACKAGE package to delete a version; $link"
elif [ -n "$LINKED" ] && [ -n "$RUNNING_IN" ] && [ "$LINKED" != "$RUNNING_IN" ]; then
  echo "note: $PACKAGE is linked to $LINKED while this workflow runs in $RUNNING_IN"
fi

plan "$WORK/versions.json" "$WORK/plan.json"
jq -r '.[] | select(.action == "delete")
       | "\(.id) \(.created_at) \(if (.tags|length) == 0 then "-" else (.tags|join(",")) end) \(.reason)"' \
  "$WORK/plan.json" >"$WORK/to-delete.txt"
SELECTED="$(wc -l <"$WORK/to-delete.txt" | tr -d ' ')"

jq -r '.[] | select(.action == "keep") | "kept, \(.reason): \(.id) \(.tags | join(","))"' "$WORK/plan.json"

if [ -n "$DRY_RUN" ]; then
  while read -r id created tags reason; do
    echo "would delete, $reason: $id $created $tags"
  done <"$WORK/to-delete.txt"
  echo "dry run: $PACKAGE keeps $(count "$WORK/plan.json" keep) of $(jq length "$WORK/plan.json") versions" \
    "($(count "$WORK/plan.json" keep "protected by tag") protected by tag," \
    "$(count "$WORK/plan.json" keep "pinned by a release") pinned by a release," \
    "$(count "$WORK/plan.json" keep "inside the newest $KEEP") inside the newest $KEEP)" \
    "and would delete $SELECTED ($(count "$WORK/plan.json" delete untagged) untagged," \
    "$(count "$WORK/plan.json" delete "older than the newest $KEEP") older than the newest $KEEP);" \
    "nothing was deleted"
  exit 0
fi

if [ "$SELECTED" -eq 0 ]; then
  echo "nothing to prune: every version is protected or inside the newest $KEEP"
  exit 0
fi
echo "selected $SELECTED versions to delete, oldest first"

DELETED=0
while read -r id created tags _; do
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
    if [ -n "$LINKED" ]; then
      echo "::error::Deleting needs the Admin role on the package and this token appears to hold Write. Grant this repository Admin on the package in the organization package settings, run the retention from the repository it is linked to ($LINKED), or supply a token carrying delete:packages."
    else
      echo "::error::Deleting needs the Admin role on the package and this token appears to hold Write. This token's answer does not name the repository the package is linked to, and the organization package settings do: grant this repository Admin on the package there, run the retention from that repository, or supply a token carrying delete:packages."
    fi
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
  plan "$WORK/after.json" "$WORK/after-plan.json"
  LEFT="$(count "$WORK/after-plan.json" delete)"
  if [ "$LEFT" = "0" ]; then
    echo "$PACKAGE is at its floor: $(jq length "$WORK/after.json") versions remain"
    exit 0
  fi
done
echo "::error::the retention floor of $PACKAGE could not be confirmed after pruning (${LEFT:-the listing failed})"
exit 1
