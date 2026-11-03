#!/usr/bin/env bash
set -euo pipefail

die() {
    echo "kind-test: $*" >&2
    exit 1
}

usage() {
    echo "kind-test: $*" >&2
    exit 2
}

cd "$(dirname "${BASH_SOURCE[0]}")/.."
root=$(pwd)
[ -f "$root/versions.env" ] || die "versions.env not found in $root"
. "$root/versions.env"

: "${KIND_VERSION:?KIND_VERSION missing in versions.env}"
: "${KIND_NODE_IMAGE:?KIND_NODE_IMAGE missing in versions.env}"

[ "$#" -le 1 ] || usage "usage: bash scripts/kind-test.sh [kshield-<name>]"
name=${1:-kshield-test-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')}
case "$name" in
    kshield-*) ;;
    *) usage "cluster name $name does not start with kshield-" ;;
esac
[[ "$name" =~ ^kshield-[a-z0-9-]{1,40}$ ]] || usage "cluster name $name must match ^kshield-[a-z0-9-]{1,40}$"

kind=$(command -v kind) || die "kind not found on PATH: install kind $KIND_VERSION"
kind_now=$("$kind" version | awk 'NR==1 {print $2}')
[ "$kind_now" = "$KIND_VERSION" ] || die "kind is $kind_now, not $KIND_VERSION"

exists() {
    local clusters
    clusters=$("$kind" get clusters 2>&1) || usage "kind get clusters failed: $clusters"
    grep -qx -- "$name" <<<"$clusters"
}

exists && usage "cluster $name already exists"

started=$(date +%s)
echo "kind-test: start $started"

kdir="$root/.kind"
kcfg="$kdir/$name.kubeconfig"
clog="$kdir/$name.create.log"
mkdir -p "$kdir"

created=0
cleanup() {
    if [ "$created" = 1 ]; then
        "$kind" delete cluster --name "$name" --kubeconfig "$kcfg" || echo "kind-test: delete of cluster $name failed" >&2
        created=0
    fi
    rm -f "$kcfg" "$clog"
}
trap cleanup EXIT

echo "== docker ps before =="
before_all=$(docker ps --format '{{.Names}}' | sort)
echo "$before_all"

echo "== kind create cluster $name =="
set +e
"$kind" create cluster \
    --name "$name" \
    --image "$KIND_NODE_IMAGE" \
    --config "$root/test/kind/kind-config.yaml" \
    --kubeconfig "$kcfg" \
    --wait 120s 2>&1 | tee "$clog"
create_rc=${PIPESTATUS[0]}
set -e
if [ "$create_rc" -ne 0 ]; then
    if (exists) || [ "$?" -ne 1 ]; then
        created=1
    fi
    die "kind create cluster failed with exit $create_rc"
fi
created=1

echo "== lsm =="
host_lsm=$(cat /sys/kernel/security/lsm)
node_lsm=$(docker exec "$name-control-plane" cat /sys/kernel/security/lsm)
echo "host: $host_lsm"
echo "node: $node_lsm"
[ -n "$host_lsm" ] || die "host /sys/kernel/security/lsm is empty"
[ "$node_lsm" = "$host_lsm" ] || die "node lsm differs from host lsm"

echo "== drift image =="
node="$name-control-plane"
images=$(docker exec "$node" ctr -n k8s.io images ls -q)
pause_ref=$(grep -m1 -E '^registry\.k8s\.io/pause:' <<<"$images" || true)
[ -n "$pause_ref" ] || die "no registry.k8s.io/pause image in the containerd cache of $node"
docker exec "$node" ctr -n k8s.io images tag --force "$pause_ref" kshield.test/vllm-pause:1
echo "tagged $pause_ref as kshield.test/vllm-pause:1 on $node"

echo "== go test -tags kind =="
KSHIELD_KIND_KUBECONFIG="$kcfg" KSHIELD_KIND_CLUSTER="$name" \
    go test -tags kind -count=1 -timeout 20m -v ./test/kind/...

echo "== kind delete cluster $name =="
cleanup
exists && die "cluster $name still exists after delete"

echo "== docker ps after =="
after_all=$(docker ps --format '{{.Names}}' | sort)
echo "$after_all"
while IFS= read -r container; do
    [ -n "$container" ] || continue
    grep -qxF -- "$container" <<<"$after_all" || die "container $container was running before the run and is gone after it"
done <<<"$before_all"

finished=$(date +%s)
echo "kind-test: end $finished, wall $((finished - started)) s"
echo "kind-test: OK"
