package report

import (
	"reflect"
	"testing"

	"github.com/sv222/kshield/internal/load"
)

func TestShowBidi(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain", "plain"},
		{"Жук 漢字 é", "Жук 漢字 é"},
		{"a\u061Cb", "a<U+061C>b"},
		{"\u200E\u200F", "<U+200E><U+200F>"},
		{"\u202A\u202B\u202C\u202D\u202E", "<U+202A><U+202B><U+202C><U+202D><U+202E>"},
		{"\u2066\u2067\u2068\u2069", "<U+2066><U+2067><U+2068><U+2069>"},
		{"evil\u202Egnp.exe", "evil<U+202E>gnp.exe"},
		{"\u200D\u2029\u202F\u2065\u206A\u2010", "\u200D\u2029\u202F\u2065\u206A\u2010"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := showBidi(tc.in); got != tc.want {
			t.Errorf("showBidi(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestForDisplayLeavesReportAlone(t *testing.T) {
	r := sampleReport()
	r.Checks[0].Findings[0].Object.Name = "a\u202Eb"
	r.Errors = []string{"e\u2066"}
	before := sampleReport()
	before.Checks[0].Findings[0].Object.Name = "a\u202Eb"
	before.Errors = []string{"e\u2066"}
	d := forDisplay(r)
	if !reflect.DeepEqual(r, before) {
		t.Fatal("forDisplay changed its input")
	}
	if got := d.Checks[0].Findings[0].Object; got != (load.ObjectRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "ai-inference", Name: "a<U+202E>b"}) {
		t.Errorf("object = %+v", got)
	}
	if d.Errors[0] != "e<U+2066>" {
		t.Errorf("error = %q", d.Errors[0])
	}
	if d.Checks[0].Findings[0].Source == r.Checks[0].Findings[0].Source {
		t.Error("source pointer is shared with the input")
	}
	if !reflect.DeepEqual(forDisplay(sampleReport()), sampleReport()) {
		t.Error("report without bidi controls must not change")
	}
}

func TestForDisplayClusterInfo(t *testing.T) {
	r := sampleReport()
	r.Scan.Cluster = &ClusterInfo{Context: "c\u202E", Server: "s\u2066", Namespaces: []string{"n\u200F"}, NodeProbe: true, ProbeNamespace: "p\u061C"}
	d := forDisplay(r)
	want := ClusterInfo{Context: "c<U+202E>", Server: "s<U+2066>", Namespaces: []string{"n<U+200F>"}, NodeProbe: true, ProbeNamespace: "p<U+061C>"}
	if !reflect.DeepEqual(*d.Scan.Cluster, want) {
		t.Errorf("cluster = %+v, want %+v", *d.Scan.Cluster, want)
	}
	if r.Scan.Cluster.Context != "c\u202E" || r.Scan.Cluster.Namespaces[0] != "n\u200F" {
		t.Error("forDisplay changed its input")
	}
}
