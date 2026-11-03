package claimcheck

import (
	"strings"

	"github.com/sv222/kshield/internal/pdftext"
)

const claimStem = "complian"

func Leak(text, disclaimer string, excerpts []string) string {
	rest := pdftext.Squash(text)
	rest = strings.ReplaceAll(rest, pdftext.Squash(disclaimer), "")
	for _, ex := range excerpts {
		rest = strings.ReplaceAll(rest, pdftext.Squash(ex), "")
	}
	i := strings.Index(strings.ToLower(rest), claimStem)
	if i < 0 {
		return ""
	}
	return rest[max(0, i-60):min(len(rest), i+60)]
}
