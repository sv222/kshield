#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

fail() {
    echo "helm-postrender: FAIL: $*" >&2
    exit 1
}

extract() {
    awk -v want="$2" '
        state == 0 && $0 == want { state = 1; next }
        state == 1 && /^```/ { state = 2; next }
        state == 2 && $0 == "```" { exit }
        state == 2 { print }
    ' "$1"
}


work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

export HELM_CONFIG_HOME="$work/helm/config"
export HELM_CACHE_HOME="$work/helm/cache"
export HELM_DATA_HOME="$work/helm/data"
export HELM_PLUGINS="$HELM_DATA_HOME/plugins"

bin="$work/kshield"
bundle="$work/bundle"
plugin="$work/src/kshield-postrender"
chart=test/helm/postrender-chart
release=kshield-check
ns=ai-inference

echo "== versions =="
echo "helm: $(helm version --template '{{.Version}}')"
echo "kustomize: $(kustomize version)"

echo "== build =="
CGO_ENABLED=0 go build -o "$bin" ./cmd/kshield

echo "== helm template (no post-renderer) =="
helm template "$release" "$chart" -n "$ns" >"$work/rendered.yaml"
cat "$work/rendered.yaml"
grep -q 'app.kubernetes.io/managed-by: Helm' "$work/rendered.yaml" || fail "rendered chart has no Helm label"
if grep -q 'runAsNonRoot' "$work/rendered.yaml"; then
    fail "control: the chart already sets runAsNonRoot"
fi
grep -q -- '--trust-remote-code' "$work/rendered.yaml" || fail "control: the chart has no --trust-remote-code"
if grep -q 'namespace:' "$work/rendered.yaml"; then
    fail "control: the chart sets metadata.namespace"
fi

echo "== scan =="
rc=0
"$bin" scan manifest -f "$work/rendered.yaml" -n "$ns" --format json --deterministic --out "$work/scan.json" || rc=$?
echo "scan exit: $rc"
[ "$rc" -eq 1 ] || fail "scan exit $rc, want 1 (the chart has FAIL findings)"

echo "== remediate =="
"$bin" remediate --from "$work/scan.json" --out "$bundle"
echo "--- kustomization.yaml"
cat "$bundle/kustomization.yaml"

echo "== MANUAL.md Helm section =="
sed -n '/^## Helm-managed objects$/,/^## Residual items$/p' "$bundle/MANUAL.md" | sed '$d'
grep -q "^- \`Deployment/$ns/$release-vllm\`\$" "$bundle/MANUAL.md" || fail "MANUAL.md does not list the Deployment"

echo "== install the post-renderer from MANUAL.md =="
mkdir -p "$plugin" "$HELM_PLUGINS"
extract "$bundle/MANUAL.md" '`kshield-postrender/plugin.yaml`:' >"$plugin/plugin.yaml"
extract "$bundle/MANUAL.md" '`kshield-postrender/postrender.sh`:' >"$plugin/postrender.sh"
[ -s "$plugin/plugin.yaml" ] || fail "no plugin.yaml in MANUAL.md"
[ -s "$plugin/postrender.sh" ] || fail "no postrender.sh in MANUAL.md"
chmod +x "$plugin/postrender.sh"
(cd "$work/src" && helm plugin install ./kshield-postrender)
helm plugin list

echo "== helm template --post-renderer =="
helm template "$release" "$chart" -n "$ns" \
    --post-renderer kshield-postrender \
    --post-renderer-args "$bundle" \
    --post-renderer-args "$ns" >"$work/post.yaml"
cat "$work/post.yaml"

echo "== assert =="
grep -q '^kind: Deployment$' "$work/post.yaml" || fail "no Deployment after post-render"
grep -q "^  namespace: $ns\$" "$work/post.yaml" || fail "the Deployment has no namespace $ns"
grep -q '^ *runAsNonRoot: true$' "$work/post.yaml" || fail "the Deployment has no runAsNonRoot: true"
if grep -q -- '--trust-remote-code' "$work/post.yaml"; then
    fail "--trust-remote-code is still in the Deployment"
fi
grep -q -- '- --load-format' "$work/post.yaml" || fail "the JSON 6902 patch did not add --load-format"
echo "runAsNonRoot: true (strategic merge patch), --trust-remote-code removed (JSON 6902 patch), namespace $ns set"

echo "== control: post-renderer without the namespace step =="
cp -R "$bundle" "$work/raw"
cp "$work/rendered.yaml" "$work/raw/base/manifests.yaml"
rc=0
kustomize build "$work/raw" >"$work/raw.out" 2>&1 || rc=$?
echo "kustomize build over the raw output of Helm: exit $rc"
tail -n 1 "$work/raw.out"
[ "$rc" -ne 0 ] || fail "control: the bundle applied to objects without a namespace"

echo "helm-postrender: OK"
