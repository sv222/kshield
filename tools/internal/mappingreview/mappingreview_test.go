package mappingreview

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sv222/kshield/internal/check"
	"github.com/sv222/kshield/internal/profile"
	"github.com/sv222/kshield/internal/regtext"
)

const (
	hashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hashB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func loadDora(t *testing.T) *profile.Profile {
	t.Helper()
	p, err := profile.Load("dora")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func renderDora(t *testing.T) string {
	t.Helper()
	head, err := Render(loadDora(t))
	if err != nil {
		t.Fatal(err)
	}
	return head
}

func TestRenderCoversEveryRef(t *testing.T) {
	p := loadDora(t)
	head := renderDora(t)
	for _, want := range []string{
		"# Mapping review - " + p.Title + "\n",
		"`" + p.ID + "`",
		"`" + p.SHA256 + "`",
	} {
		if !strings.Contains(head, want) {
			t.Errorf("head has no %q", want)
		}
	}
	refs := 0
	for id, e := range p.Checks {
		if !strings.Contains(head, "## "+e.Display+" ("+id+")\n") {
			t.Errorf("%s: no section heading", id)
		}
		for _, ref := range e.Refs {
			ex, src, ok := regtext.Lookup(ref)
			if !ok {
				t.Fatalf("%s: ref %s does not resolve", id, ref)
			}
			refs++
			for _, want := range []string{"`" + ref + "`", regtext.Label(ref), src.CELEX, src.URL} {
				if !strings.Contains(head, want) {
					t.Errorf("%s: ref %s: head has no %q", id, ref, want)
				}
			}
			for _, line := range strings.Split(ex.Text, "\n") {
				want := ">\n"
				if line != "" {
					want = "> " + line + "\n"
				}
				if !strings.Contains(head, want) {
					t.Errorf("%s: ref %s: head has no quote line %q", id, ref, want)
				}
			}
		}
	}
	if refs == 0 {
		t.Fatal("dora profile has no refs")
	}
}

func TestRenderCatalogOrder(t *testing.T) {
	p := loadDora(t)
	head := renderDora(t)
	last := -1
	for _, c := range check.All() {
		i := strings.Index(head, "## "+p.Checks[c.ID].Display+" ("+c.ID+")\n")
		if i < 0 {
			t.Fatalf("%s: no section", c.ID)
		}
		if i <= last {
			t.Fatalf("%s: section out of catalog order", c.ID)
		}
		last = i
		if !strings.Contains(head[i:], "- Title: "+c.Title+"\n") {
			t.Errorf("%s: no title line", c.ID)
		}
	}
}

func TestRenderQuoteStaysWhole(t *testing.T) {
	head := renderDora(t)
	want := "> Financial entities shall have in place mechanisms to promptly detect anomalous activities"
	i := strings.Index(head, want)
	if i < 0 {
		t.Fatalf("head has no dora-art10-1 quote")
	}
	block := head[i:]
	block = block[:strings.Index(block, "\n\n")]
	lines := strings.Split(block, "\n")
	if len(lines) != 3 {
		t.Fatalf("quote has %d lines, want 3: %q", len(lines), block)
	}
	for _, l := range lines {
		if !strings.HasPrefix(l, ">") {
			t.Errorf("quote line %q does not start with >", l)
		}
	}
}

func TestRenderUnknownRef(t *testing.T) {
	p := loadDora(t)
	e := p.Checks["KS-WL-001"]
	e.Refs = []string{"no-such-ref"}
	p.Checks["KS-WL-001"] = e
	if _, err := Render(p); err == nil || !strings.Contains(err.Error(), "no-such-ref") {
		t.Fatalf("err = %v, want error naming no-such-ref", err)
	}
}

func TestRenderHasNoMarker(t *testing.T) {
	if strings.Contains(renderDora(t), Marker) {
		t.Fatal("head contains the marker")
	}
}

func TestRenderNamesReviewSHA(t *testing.T) {
	if !strings.Contains(renderDora(t), "The row also carries the review sha256 that `go run ./tools/mappingreview` prints.") {
		t.Fatal("sign-off instruction does not mention the review sha256")
	}
}

func TestNewFile(t *testing.T) {
	head := renderDora(t)
	out := filepath.Join(t.TempDir(), "MAPPING-REVIEW.md")
	if err := Update(out, head); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	want := head + Marker + "\n\n## Sign-off\n\n| Date | Name | Profile sha256 | Review sha256 | Decision |\n|---|---|---|---|---|\n"
	if string(got) != want {
		t.Fatalf("new file tail:\n%s", strings.TrimPrefix(string(got), head))
	}
}

func TestNewFileHeader(t *testing.T) {
	head := renderDora(t)
	out := filepath.Join(t.TempDir(), "MAPPING-REVIEW.md")
	if err := Update(out, head); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	_, tail, ok := Split(string(got))
	if !ok {
		t.Fatal("new file has no marker")
	}
	if !strings.Contains(tail, TableHeader+"\n|---|---|---|---|---|\n") {
		t.Fatalf("tail has no 5 column table:\n%s", tail)
	}
	if n := strings.Count(TableHeader, "|") - 1; n != 5 {
		t.Fatalf("TableHeader has %d columns", n)
	}
	rows, err := ParseSignOff(tail)
	if err != nil || len(rows) != 0 {
		t.Fatalf("rows %v, err %v", rows, err)
	}
}

func TestKeepsSignOff(t *testing.T) {
	head := renderDora(t)
	tail := Marker + "\n\n## Sign-off\n\nNotes kept as is.  \n\n" + TableHeader + "\n|---|---|---|---|---|\n| 2026-10-17 | Owner | abc123 | def456 | approved |\n"
	out := filepath.Join(t.TempDir(), "MAPPING-REVIEW.md")
	if err := os.WriteFile(out, []byte("# Old head\n\nstale text\n\n"+tail), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Update(out, head); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != head+tail {
		t.Fatalf("got:\n%s", got)
	}
}

func TestMarkerMustStartLine(t *testing.T) {
	out := filepath.Join(t.TempDir(), "MAPPING-REVIEW.md")
	old := []byte("# Old\n\ntext " + Marker + "\n| 2026-10-17 | Owner | abc | approved |\n")
	if err := os.WriteFile(out, old, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Update(out, "# New\n\n"); err == nil {
		t.Fatal("Update accepted a marker inside a line")
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, old) {
		t.Fatal("file changed after error")
	}
}

func TestNoMarkerFails(t *testing.T) {
	out := filepath.Join(t.TempDir(), "MAPPING-REVIEW.md")
	old := []byte("# Hand written\n\n| 2026-10-17 | Owner | abc | approved |\n")
	if err := os.WriteFile(out, old, 0o644); err != nil {
		t.Fatal(err)
	}
	err := Update(out, "# New\n\n")
	if err == nil || !strings.Contains(err.Error(), "marker") {
		t.Fatalf("err = %v, want marker error", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, old) {
		t.Fatal("file changed after error")
	}
}

func TestSplit(t *testing.T) {
	head, tail, ok := Split("a\nb\n" + Marker + "\nc\n")
	if !ok || head != "a\nb\n" || tail != Marker+"\nc\n" {
		t.Fatalf("head %q tail %q ok %v", head, tail, ok)
	}
	if _, _, ok := Split("a\nx " + Marker + "\n"); ok {
		t.Fatal("marker inside a line was accepted")
	}
}

func tailWith(rows ...string) string {
	return Marker + "\n\n## Sign-off\n\n" + TableHeader + "\n|---|---|---|---|---|\n" + strings.Join(rows, "")
}

func row(date, name, profileHash, reviewHash, decision string) string {
	return "| " + date + " | " + name + " | " + profileHash + " | " + reviewHash + " | " + decision + " |\n"
}

func TestParseSignOffCommitted(t *testing.T) {
	b, err := os.ReadFile("../../../docs/MAPPING-REVIEW.md")
	if err != nil {
		t.Fatal(err)
	}
	_, tail, ok := Split(string(b))
	if !ok {
		t.Fatal("committed file has no marker")
	}
	if _, err := ParseSignOff(tail); err != nil {
		t.Fatal(err)
	}
}

func TestParseSignOffRows(t *testing.T) {
	tail := tailWith(
		row("2026-10-17", "Stanislav", hashA, hashB, "approved"),
		"\nNote line that is not a row.\n",
		row("2026-10-18", "Owner Two", hashB, hashA, "rejected"),
	)
	rows, err := ParseSignOff(tail)
	if err != nil {
		t.Fatal(err)
	}
	want := []SignOff{
		{Line: 7, Date: "2026-10-17", Name: "Stanislav", ProfileSHA256: hashA, ReviewSHA256: hashB, Decision: "approved"},
		{Line: 10, Date: "2026-10-18", Name: "Owner Two", ProfileSHA256: hashB, ReviewSHA256: hashA, Decision: "rejected"},
	}
	if len(rows) != len(want) {
		t.Fatalf("rows %+v", rows)
	}
	for i := range want {
		if rows[i] != want[i] {
			t.Errorf("row %d = %+v, want %+v", i, rows[i], want[i])
		}
	}
}

func TestParseSignOffCRLF(t *testing.T) {
	tail := strings.ReplaceAll(tailWith(row("2026-10-17", "Owner", hashA, hashB, "approved")), "\n", "\r\n")
	rows, err := ParseSignOff(tail)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %v err %v", rows, err)
	}
}

func TestParseSignOffBad(t *testing.T) {
	good := row("2026-10-17", "Owner", hashA, hashB, "approved")
	cases := []struct {
		name string
		tail string
		want string
	}{
		{"4 cells", tailWith(good, "| 2026-10-17 | Owner | "+hashA+" | approved |\n"), "line 8"},
		{"6 cells", tailWith("| 2026-10-17 | Owner | " + hashA + " | " + hashB + " | approved | x |\n"), "line 7"},
		{"Approved", tailWith(row("2026-10-17", "Owner", hashA, hashB, "Approved")), "line 7"},
		{"approve", tailWith(row("2026-10-17", "Owner", hashA, hashB, "approve")), "line 7"},
		{"month 13", tailWith(row("2026-13-01", "Owner", hashA, hashB, "approved")), "line 7"},
		{"day 30 of Feb", tailWith(row("2026-02-30", "Owner", hashA, hashB, "approved")), "line 7"},
		{"short date", tailWith(row("2026-1-1", "Owner", hashA, hashB, "approved")), "line 7"},
		{"short profile hash", tailWith(row("2026-10-17", "Owner", hashA[:63], hashB, "approved")), "line 7"},
		{"short review hash", tailWith(good, row("2026-10-17", "Owner", hashA, hashB[:10], "approved")), "line 8"},
		{"upper case hash", tailWith(row("2026-10-17", "Owner", strings.ToUpper(hashA), hashB, "approved")), "line 7"},
		{"empty name", tailWith(row("2026-10-17", "", hashA, hashB, "approved")), "line 7"},
		{"no closing pipe", tailWith("| 2026-10-17 | Owner | " + hashA + " | " + hashB + " | approved\n"), "line 7"},
		{"no heading", Marker + "\n\n" + TableHeader + "\n|---|---|---|---|---|\n", "Sign-off"},
		{"second heading", tailWith(good) + "\n## Sign-off\n\n" + TableHeader + "\n|---|---|---|---|---|\n", "second"},
		{"no header", Marker + "\n\n## Sign-off\n\n" + good, "header"},
		{"old 4 column header", Marker + "\n\n## Sign-off\n\n| Date | Name | Profile sha256 | Decision |\n|---|---|---|---|\n", "line 5"},
		{"old separator", Marker + "\n\n## Sign-off\n\n" + TableHeader + "\n|---|---|---|---|\n", "separator"},
		{"nothing after heading", Marker + "\n\n## Sign-off\n", "header"},
	}
	for _, c := range cases {
		rows, err := ParseSignOff(c.tail)
		if err == nil {
			t.Errorf("%s: no error, rows %+v", c.name, rows)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q has no %q", c.name, err, c.want)
		}
	}
}

func TestReviewSHA256(t *testing.T) {
	head := renderDora(t)
	file := head + Marker + "\n\n## Sign-off\n"
	got, _, ok := Split(file)
	if !ok {
		t.Fatal("no marker")
	}
	sum := sha256.Sum256([]byte(head))
	if want := hex.EncodeToString(sum[:]); ReviewSHA256(got) != want {
		t.Fatalf("ReviewSHA256 = %s, want %s", ReviewSHA256(got), want)
	}
	if ReviewSHA256(head+"x") == ReviewSHA256(head) {
		t.Fatal("hash ignores a change")
	}
	if len(ReviewSHA256("")) != 64 {
		t.Fatal("hash is not 64 hex characters")
	}
}

func TestReviewSHA256MatchesSha256sum(t *testing.T) {
	path, err := exec.LookPath("sha256sum")
	if err != nil {
		t.Skip("sha256sum is not on PATH")
	}
	head := "fixture head\n\ntwo lines\n"
	file := filepath.Join(t.TempDir(), "head.md")
	if err := os.WriteFile(file, []byte(head+Marker+"\n\n## Sign-off\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, _, ok := Split(mustRead(t, file))
	if !ok {
		t.Fatal("no marker")
	}
	headFile := filepath.Join(t.TempDir(), "head-only.md")
	if err := os.WriteFile(headFile, []byte(got), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(path, headFile).Output()
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 || ReviewSHA256(got) != fields[0] {
		t.Fatalf("ReviewSHA256 = %s, sha256sum = %q", ReviewSHA256(got), out)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
