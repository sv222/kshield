package htmlcheck

import (
	"reflect"
	"testing"
)

const head = `<!DOCTYPE html><html><head>` + CSPMeta + `<style>p{color:red}</style></head><body>`

func TestNoNetworkClean(t *testing.T) {
	page := head + `<p>kshield &lt;script&gt; text</p><a href="https://eur-lex.europa.eu/">EUR-Lex</a></body></html>`
	if got := NoNetwork([]byte(page)); len(got) != 0 {
		t.Fatalf("clean page has violations: %v", got)
	}
}

func TestNoNetworkEachViolation(t *testing.T) {
	page := `<!DOCTYPE html><html><head><SCRIPT>x()</SCRIPT><link rel="stylesheet" href="a.css">` +
		`<style>@import "b.css"; body{background:URL(c.png)}</style></head>` +
		`<body><img src="https://example.com/d.png"></body></html>`
	want := []string{
		`forbidden "<script" found`,
		`forbidden "src=" found`,
		`forbidden "<link" found`,
		`forbidden "@import" found`,
		`forbidden "url(" found`,
		"missing CSP meta " + CSPMeta,
	}
	if got := NoNetwork([]byte(page)); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestNoNetworkOneViolation(t *testing.T) {
	page := head + `<iframe src="x.html"></iframe></body></html>`
	want := []string{`forbidden "src=" found`}
	if got := NoNetwork([]byte(page)); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}
