package clustertest_test

import (
	"slices"
	"testing"

	"github.com/sv222/kshield/internal/cluster"
	"github.com/sv222/kshield/internal/cluster/clustertest"
)

func TestKindsMatchReadSet(t *testing.T) {
	var got, want []string
	for _, k := range clustertest.Kinds {
		got = append(got, k.Group+"/"+k.Resource)
	}
	for _, r := range cluster.ReadSet() {
		want = append(want, r.Group+"/"+r.Resource)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("kinds differ from the read set:\n got %q\nwant %q", got, want)
	}
}
