package pdftext

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"codeberg.org/go-pdf/fpdf"
	"golang.org/x/image/font/gofont/gobold"
	"golang.org/x/image/font/gofont/goregular"
)

func fpdfDoc(t *testing.T, pages [][]string) []byte {
	t.Helper()
	p := fpdf.New("P", "mm", "A4", "")
	p.SetCreationDate(time.Unix(0, 0).UTC())
	p.SetModificationDate(time.Unix(0, 0).UTC())
	p.AddUTF8FontFromBytes("go", "", goregular.TTF)
	p.AddUTF8FontFromBytes("go", "B", gobold.TTF)
	for _, lines := range pages {
		p.AddPage()
		for i, l := range lines {
			if i%2 == 0 {
				p.SetFont("go", "", 10)
			} else {
				p.SetFont("go", "B", 12)
			}
			p.Text(20, float64(20+10*i), l)
		}
	}
	var b bytes.Buffer
	if err := p.Output(&b); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestExtractFPDF(t *testing.T) {
	pages := [][]string{
		{"Grüße ä é ’ Ж", "(x) \\ y ) (", "Жук and plain"},
		{"page two"},
	}
	got, err := Extract(fpdfDoc(t, pages))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{strings.Join(pages[0], "\n"), "page two"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestRunsFPDF(t *testing.T) {
	pages, err := Runs(fpdfDoc(t, [][]string{{"regular", "bold"}}))
	if err != nil {
		t.Fatal(err)
	}
	if len(pages) != 1 || len(pages[0]) != 2 {
		t.Fatalf("runs = %+v", pages)
	}
	reg, bold := pages[0][0], pages[0][1]
	k := 72 / 25.4
	if reg.Size != 10 || bold.Size != 12 {
		t.Errorf("sizes = %v, %v", reg.Size, bold.Size)
	}
	if !near(reg.X, 20*k) || !near(reg.Y, (297-20)*k) || !near(bold.Y, (297-30)*k) {
		t.Errorf("positions = %+v %+v", reg, bold)
	}
	if reg.Font != "utf8go" || bold.Font != "utf8goB" {
		t.Errorf("fonts = %q, %q", reg.Font, bold.Font)
	}
}

func near(a, b float64) bool {
	return a-b < 0.01 && b-a < 0.01
}

func handmade() []byte {
	cmap := "/CIDInit /ProcSet findresource begin\nbegincmap\n1 begincodespacerange\n<00> <FF>\nendcodespacerange\n" +
		"2 beginbfchar\n<01> <0416>\n<02> <00E9>\nendbfchar\n" +
		"2 beginbfrange\n<10> <12> <0061>\n<20> <21> [<2019> <00E4>]\nendbfrange\nendcmap\n"
	content := "BT /F1 12 Tf 10 20 Td <01 02 10 11 12 20 21> Tj ET\n" +
		"% a comment (not text)\n" +
		"q << /MCID 0 >> BDC Q\n" +
		"BT /F2 9 Tf 1 0 0 1 30 40 Tm [(Hi) -250 (\\050x\\051 \\\\ \\101\\n)] TJ 0 -10 Td (nested (ok)) Tj ET\n"
	objs := []string{
		"<< /Type /Pages /Kids [2 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 1 0 R /Resources << /Font << /F1 3 0 R /F2 5 0 R >> >> /Contents 4 0 R >>",
		"<< /Type /Font /BaseFont /Custom /ToUnicode 6 0 R >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(content), content),
		"<< /Type /Font /BaseFont /Helvetica >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(cmap), cmap),
	}
	var b strings.Builder
	b.WriteString("%PDF-1.4\n")
	for i, o := range objs {
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, o)
	}
	b.WriteString("trailer << /Root 1 0 R >>\n%%EOF\n")
	return []byte(b.String())
}

func TestRunsHandmade(t *testing.T) {
	pages, err := Runs(handmade())
	if err != nil {
		t.Fatal(err)
	}
	want := [][]Run{{
		{Font: "Custom", Size: 12, X: 10, Y: 20, Text: "Жéabc’ä"},
		{Font: "Helvetica", Size: 9, X: 30, Y: 40, Text: "Hi(x) \\ A\n"},
		{Font: "Helvetica", Size: 9, X: 30, Y: 30, Text: "nested (ok)"},
	}}
	if !reflect.DeepEqual(pages, want) {
		t.Fatalf("got  %+v\nwant %+v", pages, want)
	}
}

func TestExtractErrors(t *testing.T) {
	for name, in := range map[string][]byte{
		"not a pdf":   []byte("hello"),
		"open object": []byte("1 0 obj << /Type /Pages /Kids [] >>"),
		"bad filter":  []byte("1 0 obj << /Type /Pages /Kids [2 0 R] >> endobj 2 0 obj << /Type /Page /Parent 1 0 R /Contents 3 0 R >> endobj 3 0 obj << /Length 1 /Filter /LZWDecode >>\nstream\nx\nendstream endobj"),
	} {
		if _, err := Extract(in); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestSquash(t *testing.T) {
	if got := Squash("a b\tc\n d e\r\n"); got != "abcde" {
		t.Fatalf("got %q", got)
	}
}
