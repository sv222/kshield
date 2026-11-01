package claimcheck

import "testing"

func TestComplianceLeak(t *testing.T) {
	disclaimer := "Sample notice. It does not state compliance with any rule."
	ex := []string{"an excerpt that names compliance\nwith a rule"}
	cases := []struct {
		name, text string
		leak       bool
	}{
		{"no claim", "Title\nBody", false},
		{"disclaimer only", "Title\n" + disclaimer + "\nBody", false},
		{"disclaimer rewrapped", "Sample notice.\n  It does not state\ncompliance with any rule.", false},
		{"excerpt rewrapped", "<blockquote>an excerpt that names\n   compliance with a rule</blockquote>", false},
		{"excerpt indented", "Ref\n  an excerpt that names\n  compliance with a rule\n", false},
		{"claim", disclaimer + " This cluster is DORA Compliant.", true},
		{"claim upper case", "FULLY COMPLIANT", true},
		{"claim next to excerpt", "an excerpt that names compliance with a rule, fully compliant", true},
		{"part of the disclaimer", "does not state compliance with any rule", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Leak(tc.text, disclaimer, ex) != ""; got != tc.leak {
				t.Fatalf("leak = %v, want %v", got, tc.leak)
			}
		})
	}
}

func TestLeakFragment(t *testing.T) {
	if got := Leak("abc compliant xyz", "", nil); got != "abccompliantxyz" {
		t.Fatalf("fragment %q", got)
	}
}
