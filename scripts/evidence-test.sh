#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

fail() {
    echo "evidence-test: FAIL: $*" >&2
    exit 1
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

bin="$work/kshield"
pack="$work/pack"
input=test/corpus/baseline/toxic/input.yaml

echo "== build =="
CGO_ENABLED=0 go build -o "$bin" ./cmd/kshield

echo "== keygen =="
"$bin" evidence keygen --out "$work/sign"
"$bin" evidence keygen --out "$work/other"

echo "== scan manifest with evidence =="
rc=0
"$bin" scan manifest -f "$input" --evidence "$pack" --sign-key "$work/sign.key" --deterministic >"$work/scan.txt" || rc=$?
echo "scan exit: $rc"
[ "$rc" -eq 1 ] || fail "scan exit $rc, want 1 (toxic has FAIL findings)"
for f in "$pack"/*; do
    echo "$(basename "$f") $(wc -c <"$f") bytes"
done
total=0
for f in "$pack"/*; do
    total=$(( total + $(wc -c <"$f") ))
done
echo "pack total $total bytes"
echo "report.pdf page tree: $(grep -a -o '/Count [0-9]*' "$pack/report.pdf" | tr '\n' ' ')"
echo "report.pdf page objects: $(grep -a -c '/Type /Page$' "$pack/report.pdf")"
echo "summary: $(tr -d ' \n' <"$pack/manifest.json" | grep -o '"summary":{[^}]*}')"

echo "== verify signed pack =="
rc=0
"$bin" evidence verify "$pack" --pub-key "$work/sign.pub" || rc=$?
echo "verify exit: $rc"
[ "$rc" -eq 0 ] || fail "verify exit $rc, want 0"

echo "== control: verify with another public key =="
rc=0
out=$("$bin" evidence verify "$pack" --pub-key "$work/other.pub") || rc=$?
echo "$out"
echo "verify exit: $rc"
[ "$rc" -eq 1 ] || fail "verify with another key exit $rc, want 1"
grep -qx 'signature: invalid' <<<"$out" || fail "verify with another key did not print signature: invalid"

echo "== control: flip one byte of report.json =="
target="$pack/report.json"
offset=$(( $(wc -c <"$target") / 2 ))
old=$(od -An -tu1 -j "$offset" -N1 "$target" | tr -d ' ')
new=$(( old ^ 1 ))
printf "\\$(printf '%03o' "$new")" | dd of="$target" bs=1 seek="$offset" conv=notrunc status=none
echo "offset $offset: $old -> $new"
rc=0
out=$("$bin" evidence verify "$pack" --pub-key "$work/sign.pub") || rc=$?
echo "$out"
echo "verify exit: $rc"
[ "$rc" -eq 1 ] || fail "verify of tampered pack exit $rc, want 1"
grep -qx 'changed: report.json' <<<"$out" || fail "verify of tampered pack did not print changed: report.json"

echo "evidence-test: OK"
