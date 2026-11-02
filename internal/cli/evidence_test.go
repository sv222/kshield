package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sv222/kshield/internal/evidence"
)

func keygen(t *testing.T) string {
	t.Helper()
	prefix := filepath.Join(t.TempDir(), "signer")
	code, out, errs := run(t, "", "evidence", "keygen", "--out", prefix)
	if code != ExitOK || errs != "" {
		t.Fatalf("keygen: code=%d stdout=%q stderr=%q", code, out, errs)
	}
	return prefix
}

func scanPack(t *testing.T, prefix string) string {
	t.Helper()
	return scanPackFrom(t, writeManifest(t, "in.yaml", rootVLLMDeployment), prefix)
}

func scanPackFrom(t *testing.T, path, prefix string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "pack")
	args := []string{"scan", "manifest", "-f", path, "--deterministic", "--evidence", dir}
	if prefix != "" {
		args = append(args, "--sign-key", prefix+".key")
	}
	code, _, errs := run(t, "", args...)
	if code != ExitFindings || errs != "" {
		t.Fatalf("scan: code=%d stderr=%q", code, errs)
	}
	return dir
}

func verifyOut(t *testing.T, args ...string) (int, string) {
	t.Helper()
	code, out, errs := run(t, "", append([]string{"evidence", "verify"}, args...)...)
	if errs != "" {
		t.Fatalf("verify %v: stderr=%q", args, errs)
	}
	return code, out
}

func TestEvidenceScanAndVerify(t *testing.T) {
	prefix := keygen(t)
	dir := scanPack(t, prefix)
	code, out := verifyOut(t, dir, "--pub-key", prefix+".pub")
	if code != ExitOK || out != "signature: valid\nevidence: OK\n" {
		t.Fatalf("code=%d stdout=%q", code, out)
	}
	code, out = verifyOut(t, "--pub-key", prefix+".pub", dir)
	if code != ExitOK || out != "signature: valid\nevidence: OK\n" {
		t.Fatalf("flag first: code=%d stdout=%q", code, out)
	}
	path := filepath.Join(dir, "report.html")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b[0] ^= 0x01
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	code, out = verifyOut(t, dir, "--pub-key", prefix+".pub")
	if code != ExitFindings || out != "changed: report.html\nsignature: valid\nevidence: FAILED\n" {
		t.Fatalf("code=%d stdout=%q", code, out)
	}
}

func TestEvidencePackMatchesScanOutput(t *testing.T) {
	path := writeManifest(t, "in.yaml", rootVLLMDeployment)
	dir := filepath.Join(t.TempDir(), "pack")
	code, out, errs := run(t, "", "scan", "manifest", "-f", path, "--deterministic", "--format", "json", "--evidence", dir)
	if code != ExitFindings || errs != "" {
		t.Fatalf("code=%d stderr=%q", code, errs)
	}
	b, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != out {
		t.Fatal("report.json in the pack differs from the scan output")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if want := "manifest.json report.html report.json report.pdf report.sarif report.txt"; strings.Join(names, " ") != want {
		t.Fatalf("pack holds %v", names)
	}
}

func TestEvidenceVerifyMissingAndExtra(t *testing.T) {
	dir := scanPack(t, "")
	if err := os.Remove(filepath.Join(dir, "report.pdf")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "report.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out := verifyOut(t, dir)
	want := "missing: report.pdf\nchanged: report.txt\nextra: notes.txt\nsignature: absent\nevidence: FAILED\n"
	if code != ExitFindings || out != want {
		t.Fatalf("code=%d stdout=%q want %q", code, out, want)
	}
}

func TestEvidenceVerifyHostileExtraName(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("newline in a file name is not allowed on Windows")
	}
	dir := scanPack(t, "")
	if err := os.WriteFile(filepath.Join(dir, "x\nevidence: OK"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out := verifyOut(t, dir)
	want := "extra: \"x\\nevidence: OK\"\nsignature: absent\nevidence: FAILED\n"
	if code != ExitFindings || out != want {
		t.Fatalf("code=%d stdout=%q want %q", code, out, want)
	}
}

func TestEvidenceVerifySignatureStates(t *testing.T) {
	prefix := keygen(t)
	other := keygen(t)
	signed := scanPack(t, prefix)
	unsigned := scanPack(t, "")
	cases := []struct {
		name string
		args []string
		code int
		out  string
	}{
		{"wrong key", []string{signed, "--pub-key", other + ".pub"}, ExitFindings, "signature: invalid\nevidence: FAILED\n"},
		{"not checked", []string{signed}, ExitOK, "signature: not-checked\nevidence: OK\n"},
		{"unsigned", []string{unsigned}, ExitOK, "signature: absent\nevidence: OK\n"},
		{"unsigned with key", []string{unsigned, "--pub-key", prefix + ".pub"}, ExitFindings, "signature: absent\nevidence: FAILED\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, out := verifyOut(t, tc.args...)
			if code != tc.code || out != tc.out {
				t.Fatalf("code=%d stdout=%q", code, out)
			}
		})
	}
	if err := os.Remove(filepath.Join(signed, "manifest.sig")); err != nil {
		t.Fatal(err)
	}
	code, out := verifyOut(t, signed, "--pub-key", prefix+".pub")
	if code != ExitFindings || out != "signature: absent\nevidence: FAILED\n" {
		t.Fatalf("signature deleted: code=%d stdout=%q", code, out)
	}
}

func TestEvidenceNonEmptyDirRefused(t *testing.T) {
	path := writeManifest(t, "in.yaml", rootVLLMDeployment)
	dir := t.TempDir()
	old := filepath.Join(dir, "report.json")
	if err := os.WriteFile(old, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errs := run(t, "", "scan", "manifest", "-f", path, "--evidence", dir)
	if code != ExitUsage || out != "" || !strings.Contains(errs, "not empty") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errs)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("dir holds %d entries", len(entries))
	}
	if b, _ := os.ReadFile(old); string(b) != "old" {
		t.Fatalf("old file changed: %q", b)
	}
}

func TestEvidenceErrors(t *testing.T) {
	path := writeManifest(t, "in.yaml", rootVLLMDeployment)
	prefix := keygen(t)
	notPack := t.TempDir()
	badKey := writeManifest(t, "bad.key", "not a key")
	cases := []struct {
		name string
		args []string
	}{
		{"sign key without evidence", []string{"scan", "manifest", "-f", path, "--sign-key", prefix + ".key"}},
		{"bad sign key", []string{"scan", "manifest", "-f", path, "--evidence", filepath.Join(t.TempDir(), "p"), "--sign-key", badKey}},
		{"public key as sign key", []string{"scan", "manifest", "-f", path, "--evidence", filepath.Join(t.TempDir(), "p"), "--sign-key", prefix + ".pub"}},
		{"evidence no subcommand", []string{"evidence"}},
		{"evidence unknown subcommand", []string{"evidence", "sign"}},
		{"verify no dir", []string{"evidence", "verify"}},
		{"verify two dirs", []string{"evidence", "verify", notPack, notPack}},
		{"verify not a pack", []string{"evidence", "verify", notPack}},
		{"verify missing dir", []string{"evidence", "verify", filepath.Join(notPack, "none")}},
		{"verify bad pub key", []string{"evidence", "verify", notPack, "--pub-key", badKey}},
		{"verify private key as pub key", []string{"evidence", "verify", notPack, "--pub-key", prefix + ".key"}},
		{"keygen no out", []string{"evidence", "keygen"}},
		{"keygen extra arg", []string{"evidence", "keygen", "--out", filepath.Join(t.TempDir(), "k"), "x"}},
		{"keygen existing", []string{"evidence", "keygen", "--out", prefix}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errs := run(t, "", tc.args...)
			if code != ExitUsage || out != "" || !strings.HasPrefix(errs, "kshield: ") {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errs)
			}
		})
	}
}

func TestEvidenceOutInsidePackRefused(t *testing.T) {
	path := writeManifest(t, "in.yaml", rootVLLMDeployment)
	parent := t.TempDir()
	dir := filepath.Join(parent, "pack")
	t.Chdir(parent)
	for _, out := range []string{
		filepath.Join(dir, "scan.sarif"),
		dir,
		filepath.Join(dir, "sub", "..", "scan.sarif"),
		filepath.Join("pack", "scan.sarif"),
		filepath.Join(".", "pack", "deep", "scan.sarif"),
	} {
		code, stdout, errs := run(t, "", "scan", "manifest", "-f", path, "--fail-on", "never", "--format", "sarif", "--out", out, "--evidence", dir)
		if code != ExitUsage || stdout != "" || !strings.Contains(errs, "must not be inside the --evidence dir") {
			t.Fatalf("--out %s: code=%d stdout=%q stderr=%q", out, code, stdout, errs)
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatalf("--out %s: pack dir written: %v", out, err)
		}
	}
	for i, out := range []string{
		filepath.Join(parent, "pack-x", "scan.sarif"),
		filepath.Join(parent, "scan.sarif"),
	} {
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			t.Fatal(err)
		}
		pack := filepath.Join(parent, "pack"+strings.Repeat("y", i))
		code, _, errs := run(t, "", "scan", "manifest", "-f", path, "--fail-on", "never", "--format", "sarif", "--out", out, "--evidence", pack)
		if code != ExitOK || errs != "" {
			t.Fatalf("control --out %s: code=%d stderr=%q", out, code, errs)
		}
		if code, vout := verifyOut(t, pack); code != ExitOK {
			t.Fatalf("control --out %s: verify code=%d stdout=%q", out, code, vout)
		}
	}
}

func TestEvidenceBadSignKeyWritesNoPack(t *testing.T) {
	path := writeManifest(t, "in.yaml", rootVLLMDeployment)
	dir := filepath.Join(t.TempDir(), "pack")
	badKey := writeManifest(t, "bad.key", "not a key")
	if code, _, _ := run(t, "", "scan", "manifest", "-f", path, "--evidence", dir, "--sign-key", badKey); code != ExitUsage {
		t.Fatalf("code=%d", code)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("pack dir written: %v", err)
	}
}

func TestEvidenceHelp(t *testing.T) {
	for _, args := range [][]string{{"evidence", "verify", "-h"}, {"evidence", "keygen", "-h"}} {
		if code, _, errs := run(t, "", args...); code != ExitOK || !strings.Contains(errs, "kshield evidence") {
			t.Errorf("%v: code=%d stderr=%q", args, code, errs)
		}
	}
	_, out, _ := run(t, "", "help")
	for _, want := range []string{
		"[--evidence <dir> [--sign-key <file>]]",
		"kshield evidence verify <dir> [--pub-key <file>]",
		"kshield evidence keygen --out <prefix>",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("usage misses %q", want)
		}
	}
	_, _, errs := run(t, "", "scan", "manifest", "-h")
	if !strings.Contains(errs, "[--evidence <dir> [--sign-key <file>]]") {
		t.Errorf("scan manifest usage: %q", errs)
	}
}

func TestKeyNeverPrinted(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "signer")
	code, kout, kerr := run(t, "", "evidence", "keygen", "--out", prefix)
	if code != ExitOK {
		t.Fatalf("keygen code=%d", code)
	}
	keyPEM, err := os.ReadFile(prefix + ".key")
	if err != nil {
		t.Fatal(err)
	}
	priv, err := evidence.LoadPrivateKey(prefix + ".key")
	if err != nil {
		t.Fatal(err)
	}
	secrets := []string{
		"-----BEGIN",
		base64.StdEncoding.EncodeToString(priv),
		base64.StdEncoding.EncodeToString(priv.Seed()),
		base64.RawStdEncoding.EncodeToString(priv.Seed()),
		base64.URLEncoding.EncodeToString(priv.Seed()),
		hex.EncodeToString(priv.Seed()),
	}
	for _, line := range strings.Split(strings.TrimSpace(string(keyPEM)), "\n") {
		if !strings.HasPrefix(line, "-----") {
			secrets = append(secrets, line)
		}
	}
	outputs := []string{kout, kerr}
	path := writeManifest(t, "in.yaml", rootVLLMDeployment)
	for _, format := range []string{"text", "json", "html", "sarif"} {
		dir := filepath.Join(t.TempDir(), "pack")
		_, out, errs := run(t, "", "scan", "manifest", "-f", path, "--format", format, "--evidence", dir, "--sign-key", prefix+".key")
		outputs = append(outputs, out, errs)
		_, out, errs = run(t, "", "evidence", "verify", dir, "--pub-key", prefix+".pub")
		outputs = append(outputs, out, errs)
	}
	_, out, errs := run(t, "", "evidence", "verify", t.TempDir(), "--pub-key", prefix+".key")
	outputs = append(outputs, out, errs)
	_, out, errs = run(t, "", "scan", "manifest", "-f", path, "--evidence", filepath.Join(t.TempDir(), "p"), "--sign-key", prefix+".pub")
	outputs = append(outputs, out, errs)
	_, out, errs = run(t, "", "evidence", "keygen", "--out", prefix)
	outputs = append(outputs, out, errs)
	leak := func(o string) bool {
		for _, s := range secrets {
			if strings.Contains(o, s) {
				return true
			}
		}
		return false
	}
	if !leak(string(keyPEM)) || !leak("seed "+hex.EncodeToString(priv.Seed())) || !leak("key "+base64.StdEncoding.EncodeToString(priv)) {
		t.Fatal("control: the check does not find key material")
	}
	for i, o := range outputs {
		if leak(o) {
			t.Fatalf("output %d shows key material", i)
		}
	}
}

func TestPackDeterministicCLI(t *testing.T) {
	prefix := keygen(t)
	path := writeManifest(t, "in.yaml", rootVLLMDeployment)
	a := scanPackFrom(t, path, prefix)
	b := scanPackFrom(t, path, prefix)
	for _, name := range []string{"manifest.json", "manifest.sig", "report.html", "report.json", "report.pdf", "report.sarif", "report.txt"} {
		x, err := os.ReadFile(filepath.Join(a, name))
		if err != nil {
			t.Fatal(err)
		}
		y, err := os.ReadFile(filepath.Join(b, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(x, y) {
			t.Errorf("%s differs between two --deterministic packs", name)
		}
	}
}
