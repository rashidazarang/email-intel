#!/usr/bin/env bash
# Fail when the version constant, the CHANGELOG top entry, and the latest tag disagree.
# The tag check is skipped when the repo has no tags yet (first release flow).
set -euo pipefail

cd "$(dirname "$0")/.."

constant=$(grep -o 'version = "[0-9.]*"' Sources/EmailIntel/EmailIntel.swift | grep -o '[0-9.]*')
changelog=$(grep -m1 -o '^## \[[0-9.]*\]' CHANGELOG.md | grep -o '[0-9.]*')

if [ -z "$constant" ] || [ -z "$changelog" ]; then
  echo "check-versions: could not read a version. constant='$constant' changelog='$changelog'" >&2
  exit 1
fi

if [ "$constant" != "$changelog" ]; then
  echo "check-versions: EmailIntel.version is $constant but the CHANGELOG top entry is $changelog." >&2
  exit 1
fi

latest_tag=$(git tag --list 'v*' --sort=-v:refname | head -1)
if [ -n "$latest_tag" ]; then
  tag_version=${latest_tag#v}
  if [ "$tag_version" != "$constant" ]; then
    echo "check-versions: the latest tag is $latest_tag but EmailIntel.version is $constant." >&2
    echo "check-versions: bump the constant and add a CHANGELOG entry, or tag v$constant." >&2
    exit 1
  fi
fi

echo "check-versions: OK ($constant)"
