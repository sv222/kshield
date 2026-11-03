package evidence

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/image/font/gofont/gobold"
	"golang.org/x/image/font/gofont/goregular"
	"golang.org/x/image/font/sfnt"

	"github.com/sv222/kshield/internal/htmlcheck"
	"github.com/sv222/kshield/internal/pdftext"
	"github.com/sv222/kshield/internal/report"
	"github.com/sv222/kshield/internal/scan"
)

const toxicInput = "test/corpus/baseline/toxic/input.yaml"

func plainRuneCheck(t *testing.T) func(string) error {
	t.Helper()
	var fonts []*sfnt.Font
	for _, ttf := range [][]byte{goregular.TTF, gobold.TTF} {
		f, err := sfnt.Parse(ttf)
		if err != nil {
			t.Fatal(err)
		}
		fonts = append(fonts, f)
	}
	var buf sfnt.Buffer
	return func(s string) error {
		for _, r := range s {
			switch {
			case r == 0x061C, r == 0x200E, r == 0x200F, r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
				return fmt.Errorf("bidi control U+%04X", r)
			case r <= 0 || r > 0xFFFF || r == 0xFFFD:
				return fmt.Errorf("rune U+%04X outside the PDF font range", r)
			}
			for _, f := range fonts {
				idx, err := f.GlyphIndex(&buf, r)
				if err != nil || idx == 0 {
					return fmt.Errorf("no glyph for U+%04X", r)
				}
			}
		}
		return nil
	}
}

func copyPack(t *testing.T, dir, name string, mutate func([]byte) []byte) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "pack")
	if err := os.Mkdir(out, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range dirNames(t, dir) {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		if n == name {
			b = mutate(b)
		}
		if err := os.WriteFile(filepath.Join(out, n), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func TestTCREG04(t *testing.T) {
	t.Chdir("../..")
	r, err := scan.Manifest(scan.Options{Inputs: []string{toxicInput}, Namespace: "ai-inference", ProfileID: "dora", Deterministic: true})
	if err != nil {
		t.Fatal(err)
	}
	key := testKey(4)
	dir := filepath.Join(t.TempDir(), "pack")
	if err := Build(dir, r, key); err != nil {
		t.Fatal(err)
	}

	t.Run("a signed pack verifies", func(t *testing.T) {
		res := mustVerify(t, dir, pubOf(key))
		if !res.OK() || res.Signature != SignatureValid {
			t.Fatalf("verify %+v, want OK and signature %q", res, SignatureValid)
		}
	})

	t.Run("b control tampered copy fails", func(t *testing.T) {
		tampered := copyPack(t, dir, "report.json", func(b []byte) []byte {
			b[len(b)/2] ^= 0x01
			return b
		})
		res := mustVerify(t, tampered, pubOf(key))
		if res.OK() || !slices.Equal(res.Changed, []string{"report.json"}) || len(res.Missing) > 0 || len(res.Extra) > 0 {
			t.Fatalf("verify %+v, want not OK with only Changed [report.json]", res)
		}
		if res.Signature != SignatureValid {
			t.Errorf("signature %q, want %q (manifest untouched)", res.Signature, SignatureValid)
		}
	})

	t.Run("b control signature fails", func(t *testing.T) {
		const created = `"createdAt": "1970-01-01T00:00:00Z"`
		tampered := copyPack(t, dir, ManifestFile, func(b []byte) []byte {
			if bytes.Count(b, []byte(created)) != 1 {
				t.Fatalf("manifest.json does not hold %s once", created)
			}
			return bytes.Replace(b, []byte(created), []byte(`"createdAt": "1971-01-01T00:00:00Z"`), 1)
		})
		for _, c := range []struct {
			name string
			dir  string
			pub  ed25519.PublicKey
		}{
			{"manifest.json changed", tampered, pubOf(key)},
			{"other key", dir, pubOf(testKey(5))},
		} {
			res := mustVerify(t, c.dir, c.pub)
			if res.OK() || res.Signature != SignatureInvalid || len(res.Missing)+len(res.Changed)+len(res.Extra) > 0 {
				t.Errorf("%s: verify %+v, want not OK with signature %q and no file errors", c.name, res, SignatureInvalid)
			}
		}
	})

	t.Run("c HTML makes no network request", func(t *testing.T) {
		page, err := os.ReadFile(filepath.Join(dir, "report.html"))
		if err != nil {
			t.Fatal(err)
		}
		if v := htmlcheck.NoNetwork(page); len(v) > 0 {
			t.Fatalf("report.html: %v", v)
		}
	})

	t.Run("d PDF shows every finding and the summary", func(t *testing.T) {
		b, err := os.ReadFile(filepath.Join(dir, "report.json"))
		if err != nil {
			t.Fatal(err)
		}
		var got report.Report
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		pdf, err := os.ReadFile(filepath.Join(dir, "report.pdf"))
		if err != nil {
			t.Fatal(err)
		}
		pages, err := pdftext.Extract(pdf)
		if err != nil {
			t.Fatal(err)
		}
		all := pdftext.Squash(strings.Join(pages, "\n"))
		plain := plainRuneCheck(t)
		n := 0
		for _, c := range got.Checks {
			for _, f := range c.Findings {
				n++
				want := c.Display + " " + f.Object.String() + " " + f.Message
				if err := plain(want); err != nil {
					t.Fatalf("check %s: %q: %v; raw JSON values no longer match the PDF display form", c.ID, want, err)
				}
				if !strings.Contains(all, pdftext.Squash(want)) {
					t.Errorf("check %s: finding text %q not in PDF", c.ID, want)
				}
			}
		}
		if n == 0 {
			t.Fatal("toxic baseline gave no findings")
		}
		s := got.Summary
		row := fmt.Sprintf("%d %s %d %s %d %s %d %s %d %s",
			s.Fail, report.VerdictFail, s.Warn, report.VerdictWarn, s.Pass, report.VerdictPass, s.Info, report.VerdictInfo, s.NA, report.VerdictNA)
		if !strings.Contains(all, pdftext.Squash(row)) {
			t.Errorf("summary %q not in PDF", row)
		}
		t.Logf("%d findings, %d PDF pages, summary %s", n, len(pages), row)
	})
}
