#!/usr/bin/env bash
set -euo pipefail

die() {
    echo "fetch-crds: $*" >&2
    exit 1
}

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(dirname "$here")
[ -f "$root/versions.env" ] || die "versions.env not found in $root"
. "$root/versions.env"

: "${CILIUM_VERSION:?CILIUM_VERSION missing in versions.env}"
: "${TETRAGON_VERSION:?TETRAGON_VERSION missing in versions.env}"
: "${KYVERNO_VERSION:?KYVERNO_VERSION missing in versions.env}"

out="$root/test/crds"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

entries=(
    "cilium|cilium/cilium|$CILIUM_VERSION|pkg/k8s/apis/cilium.io/client/crds/v2/ciliumnetworkpolicies.yaml"
    "tetragon|cilium/tetragon|$TETRAGON_VERSION|pkg/k8s/apis/cilium.io/client/crds/v1alpha1/cilium.io_tracingpoliciesnamespaced.yaml"
    "kyverno|kyverno/kyverno|$KYVERNO_VERSION|config/crds/kyverno/kyverno.io_policies.yaml"
)

rows=()
for entry in "${entries[@]}"; do
    IFS='|' read -r project repo tag path <<<"$entry"
    url="https://raw.githubusercontent.com/$repo/$tag/$path"
    file="$tmp/$project/$(basename "$path")"
    mkdir -p "$tmp/$project"
    curl -fsSL --retry 3 --connect-timeout 15 -o "$file" "$url" || die "$path not found at $repo@$tag ($url)"
    sum=$(sha256sum "$file" | awk '{print $1}')
    rows+=("| \`$project/$(basename "$path")\` | $url | \`$tag\` | \`$sum\` |")
done

rm -rf "$out"
mkdir -p "$out"
cp -R "$tmp"/. "$out"/

{
    echo "# CRD sources"
    echo
    echo "Written by \`scripts/fetch-crds.sh\` from the tags in \`versions.env\`. Do not edit by hand."
    echo
    echo "| File | URL | Tag | sha256 |"
    echo "|---|---|---|---|"
    printf '%s\n' "${rows[@]}"
} >"$out/SOURCES.md"

echo "fetch-crds: wrote ${#rows[@]} files to test/crds"
