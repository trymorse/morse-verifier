#!/usr/bin/env bash
set -euo pipefail

# release-notes.sh <tag> [<npm version>]
# Prints the GitHub Release notes for a vYYYY.M.N tag of this repository: the npm version that
# carries its code, and what changed since the release before it. Run it in a full clone. The npm
# version is the one release.yml published, or, when none is given, the one npm has for any release
# tag on the same commit.

die() {
  echo "release-notes.sh: $*" >&2
  exit 1
}

[ $# -ge 1 ] && [ $# -le 2 ] || die "usage: release-notes.sh <tag> [<npm version>]"
tag=$1 npm_version=${2:-}
[[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "$tag is not a vYYYY.M.N release"
commit=$(git rev-parse --verify -q "refs/tags/$tag^{commit}") || die "no tag $tag"
repo=${GITHUB_REPOSITORY:-trymorse/morse-verifier}
releases='^v[0-9]+\.[0-9]+\.[0-9]+$'

# Release tags on one commit ship the same code, which npm has under one of their versions.
here=$(git tag --points-at "$commit" --sort=v:refname | grep -E "$releases")
if [ -z "$npm_version" ]; then
  for other in $here; do
    if [ "$(npm view "@askmorse/verify@${other#v}" version 2>/dev/null || true)" = "${other#v}" ]; then
      npm_version=${other#v}
      break
    fi
  done
fi
# shellcheck disable=SC2016 # the backticks are Markdown
if [ -n "$npm_version" ]; then
  printf 'On npm as [`@askmorse/verify@%s`](https://www.npmjs.com/package/@askmorse/verify/v/%s):\n\n' "$npm_version" "$npm_version"
  printf '```sh\nnpx -y @askmorse/verify@%s\n```\n\n' "$npm_version"
fi
first=$(head -n 1 <<<"$here")
if [ "$first" != "$tag" ]; then
  echo "This release ships the same code as [$first](https://github.com/$repo/releases/tag/$first)."
  exit 0
fi

previous=$(git tag --merged "$commit^" --sort=-v:refname 2>/dev/null | grep -E "$releases" | head -n 1 || true)
if [ -z "$previous" ]; then
  echo "The first release of this repository."
  exit 0
fi
echo "## What changed since $previous"
echo
echo "[Compare $previous...$tag](https://github.com/$repo/compare/$previous...$tag)"
echo
echo '```'
git diff --stat=100 "$previous" "$tag"
echo '```'
