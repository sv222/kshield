package htmlcheck

import (
	"bytes"
	"fmt"
)

const CSPMeta = `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">`

var forbidden = []string{"<script", "src=", "<link", "@import", "url("}

func NoNetwork(page []byte) []string {
	var out []string
	lower := bytes.ToLower(page)
	for _, f := range forbidden {
		if bytes.Contains(lower, []byte(f)) {
			out = append(out, fmt.Sprintf("forbidden %q found", f))
		}
	}
	if !bytes.Contains(page, []byte(CSPMeta)) {
		out = append(out, "missing CSP meta "+CSPMeta)
	}
	return out
}
