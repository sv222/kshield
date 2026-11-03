package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/sv222/kshield/internal/report"
)

const toxicJSON = "../../test/golden/toxic.json"

var packNames = []string{
	"manifest.json",
	"manifest.sig",
	"report.html",
	"report.json",
	"report.pdf",
	"report.sarif",
	"report.txt",
}

func toxicReport(t *testing.T) *report.Report {
	t.Helper()
	b, err := os.ReadFile(toxicJSON)
	if err != nil {
		t.Fatal(err)
	}
	var r report.Report
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return &r
}

func testKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
}

func pubOf(k ed25519.PrivateKey) ed25519.PublicKey {
	return k.Public().(ed25519.PublicKey)
}

func buildPack(t *testing.T, key ed25519.PrivateKey) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "pack")
	if err := Build(dir, toxicReport(t), key); err != nil {
		t.Fatal(err)
	}
	return dir
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

func readManifest(t *testing.T, dir string) (Manifest, []byte) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m, b
}

func mustVerify(t *testing.T, dir string, pub ed25519.PublicKey) Result {
	t.Helper()
	res, err := Verify(dir, pub)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestBuildAndVerify(t *testing.T) {
	key := testKey(1)
	r := toxicReport(t)
	dir := buildPack(t, key)
	if got := dirNames(t, dir); !slices.Equal(got, packNames) {
		t.Fatalf("pack files %v, want %v", got, packNames)
	}
	m, raw := readManifest(t, dir)
	if m.SchemaVersion != "kshield.evidence/v1" || m.CreatedAt != r.Scan.StartedAt || m.Tool != r.Tool || m.Profile != r.Profile || m.Summary != r.Summary {
		t.Fatalf("manifest header %+v", m)
	}
	if m.PublicKey != base64.StdEncoding.EncodeToString(pubOf(key)) {
		t.Fatalf("publicKey %q", m.PublicKey)
	}
	var paths []string
	for _, f := range m.Files {
		paths = append(paths, f.Path)
		b, err := os.ReadFile(filepath.Join(dir, f.Path))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		if f.SHA256 != hex.EncodeToString(sum[:]) || f.Size != int64(len(b)) {
			t.Errorf("%s: manifest %s/%d, file %x/%d", f.Path, f.SHA256, f.Size, sum, len(b))
		}
	}
	if want := []string{"report.html", "report.json", "report.pdf", "report.sarif", "report.txt"}; !slices.Equal(paths, want) {
		t.Fatalf("manifest files %v, want %v", paths, want)
	}
	if !bytes.HasSuffix(raw, []byte("}\n")) {
		t.Fatalf("manifest.json does not end with a newline")
	}
	sig, err := os.ReadFile(filepath.Join(dir, "manifest.sig"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(sig, []byte("\n")) {
		t.Fatalf("manifest.sig %q has no newline", sig)
	}
	rawSig, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(string(sig), "\n"))
	if err != nil || !ed25519.Verify(pubOf(key), raw, rawSig) {
		t.Fatalf("manifest.sig is not an ed25519 signature of manifest.json: %v", err)
	}
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "report.json")); !bytes.Equal(got, buf.Bytes()) {
		t.Fatalf("report.json differs from report.WriteJSON")
	}
	res := mustVerify(t, dir, pubOf(key))
	if !res.OK() || res.Signature != "valid" || len(res.Missing)+len(res.Changed)+len(res.Extra) != 0 {
		t.Fatalf("verify %+v", res)
	}
}

func TestPackFileModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes are not kept on Windows")
	}
	dir := buildPack(t, testKey(1))
	for _, name := range packNames {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o644 {
			t.Errorf("%s mode %v", name, info.Mode().Perm())
		}
	}
}

func TestVerifyChanged(t *testing.T) {
	key := testKey(1)
	dir := buildPack(t, key)
	path := filepath.Join(dir, "report.html")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)/2] ^= 0x01
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	res := mustVerify(t, dir, pubOf(key))
	if res.OK() || !slices.Equal(res.Changed, []string{"report.html"}) || len(res.Missing) != 0 || len(res.Extra) != 0 || res.Signature != "valid" {
		t.Fatalf("verify %+v", res)
	}
}

func TestVerifyChangedSameSize(t *testing.T) {
	dir := buildPack(t, nil)
	if err := os.WriteFile(filepath.Join(dir, "report.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := mustVerify(t, dir, nil)
	if res.OK() || !slices.Equal(res.Changed, []string{"report.txt"}) {
		t.Fatalf("verify %+v", res)
	}
}

func TestVerifyMissingAndExtra(t *testing.T) {
	key := testKey(1)
	dir := buildPack(t, key)
	if err := os.Remove(filepath.Join(dir, "report.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "report.pdf")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "extra.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "report.html")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "report.html"), 0o755); err != nil {
		t.Fatal(err)
	}
	res := mustVerify(t, dir, pubOf(key))
	if res.OK() ||
		!slices.Equal(res.Missing, []string{"report.pdf", "report.txt"}) ||
		!slices.Equal(res.Extra, []string{"extra.txt", "sub"}) ||
		!slices.Equal(res.Changed, []string{"report.html"}) ||
		res.Signature != "valid" {
		t.Fatalf("verify %+v", res)
	}
}

func TestVerifyWrongKey(t *testing.T) {
	key := testKey(1)
	dir := buildPack(t, key)
	res := mustVerify(t, dir, pubOf(testKey(2)))
	if res.OK() || res.Signature != "invalid" {
		t.Fatalf("verify %+v", res)
	}
	if len(res.Missing)+len(res.Changed)+len(res.Extra) != 0 {
		t.Fatalf("verify %+v", res)
	}
}

func TestVerifyResignedByOtherKey(t *testing.T) {
	key := testKey(1)
	other := testKey(2)
	dir := buildPack(t, key)
	m, _ := readManifest(t, dir)
	m.PublicKey = base64.StdEncoding.EncodeToString(pubOf(other))
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(other, buf.Bytes())) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "manifest.sig"), []byte(sig), 0o644); err != nil {
		t.Fatal(err)
	}
	if res := mustVerify(t, dir, pubOf(key)); res.OK() || res.Signature != "invalid" {
		t.Fatalf("verify %+v", res)
	}
	if res := mustVerify(t, dir, pubOf(other)); !res.OK() || res.Signature != "valid" {
		t.Fatalf("control: verify with the signing key %+v", res)
	}
}

func TestVerifyTamperedManifestOrSignature(t *testing.T) {
	key := testKey(1)
	cases := map[string]func(t *testing.T, dir string){
		"manifest byte": func(t *testing.T, dir string) {
			path := filepath.Join(dir, "manifest.json")
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, append(b, ' '), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"signature not base64": func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "manifest.sig"), []byte("%%%\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"signature empty": func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "manifest.sig"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"signature short": func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "manifest.sig"), []byte("AAAA\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			dir := buildPack(t, key)
			tamper(t, dir)
			if res := mustVerify(t, dir, pubOf(key)); res.OK() || res.Signature != "invalid" {
				t.Fatalf("verify %+v", res)
			}
		})
	}
}

func TestVerifyUnsigned(t *testing.T) {
	dir := buildPack(t, nil)
	if got, want := dirNames(t, dir), slices.DeleteFunc(slices.Clone(packNames), func(s string) bool { return s == "manifest.sig" }); !slices.Equal(got, want) {
		t.Fatalf("pack files %v, want %v", got, want)
	}
	if m, _ := readManifest(t, dir); m.PublicKey != "" {
		t.Fatalf("unsigned publicKey %q", m.PublicKey)
	}
	for _, pub := range []ed25519.PublicKey{nil, pubOf(testKey(1))} {
		if res := mustVerify(t, dir, pub); !res.OK() || res.Signature != "absent" {
			t.Fatalf("verify %+v", res)
		}
	}
}

func TestVerifyNotChecked(t *testing.T) {
	dir := buildPack(t, testKey(1))
	if res := mustVerify(t, dir, nil); !res.OK() || res.Signature != "not-checked" {
		t.Fatalf("verify %+v", res)
	}
}

func TestVerifyNotAPack(t *testing.T) {
	cases := map[string]string{
		"no manifest":   "",
		"not json":      "not json",
		"other schema":  `{"schemaVersion":"other/v1","files":[]}`,
		"parent path":   `{"schemaVersion":"kshield.evidence/v1","files":[{"path":"../x","sha256":"","size":0}]}`,
		"nested path":   `{"schemaVersion":"kshield.evidence/v1","files":[{"path":"a/b","sha256":"","size":0}]}`,
		"absolute path": `{"schemaVersion":"kshield.evidence/v1","files":[{"path":"/etc/passwd","sha256":"","size":0}]}`,
		"self listed":   `{"schemaVersion":"kshield.evidence/v1","files":[{"path":"manifest.sig","sha256":"","size":0}]}`,
		"duplicate":     `{"schemaVersion":"kshield.evidence/v1","files":[{"path":"a","sha256":"","size":0},{"path":"a","sha256":"","size":0}]}`,
	}
	for name, manifest := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if manifest != "" {
				if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := Verify(dir, nil); err == nil {
				t.Fatal("no error")
			}
		})
	}
	if _, err := Verify(filepath.Join(t.TempDir(), "none"), nil); err == nil {
		t.Fatal("missing dir: no error")
	}
}

func TestBuildRefusesNonEmptyDir(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "report.json")
	if err := os.WriteFile(old, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Build(dir, toxicReport(t), testKey(1)); err == nil {
		t.Fatal("no error for a non-empty dir")
	}
	if got := dirNames(t, dir); !slices.Equal(got, []string{"report.json"}) {
		t.Fatalf("dir now holds %v", got)
	}
	if b, _ := os.ReadFile(old); string(b) != "old" {
		t.Fatalf("old file changed: %q", b)
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Build(file, toxicReport(t), nil); err == nil {
		t.Fatal("no error for a file path")
	}
	empty := t.TempDir()
	if err := Build(empty, toxicReport(t), nil); err != nil {
		t.Fatalf("empty dir: %v", err)
	}
	if res := mustVerify(t, empty, nil); !res.OK() {
		t.Fatalf("verify %+v", res)
	}
}

func TestBuildRenderErrorLeavesNoPack(t *testing.T) {
	r := toxicReport(t)
	for i := range r.Checks {
		if len(r.Checks[i].Findings) > 0 {
			r.Checks[i].Refs = append(r.Checks[i].Refs, report.Ref{ID: "no-such-ref"})
			break
		}
	}
	dir := filepath.Join(t.TempDir(), "pack")
	if err := Build(dir, r, nil); err == nil {
		t.Fatal("no error for a report that cannot render")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("pack dir left behind: %v", err)
	}
}

func TestManifestInputs(t *testing.T) {
	r := toxicReport(t)
	if len(r.Scan.InputDigests) == 0 {
		t.Fatal("toxic report has no input digests")
	}
	m, _ := readManifest(t, buildPack(t, nil))
	if !reflect.DeepEqual(m.Inputs, r.Scan.InputDigests) {
		t.Fatalf("inputs %v, want %v", m.Inputs, r.Scan.InputDigests)
	}
	r.Scan.InputDigests = nil
	dir := filepath.Join(t.TempDir(), "pack")
	if err := Build(dir, r, nil); err != nil {
		t.Fatal(err)
	}
	if _, raw := readManifest(t, dir); !bytes.Contains(raw, []byte(`"inputs": []`)) {
		t.Fatalf("nil inputs not written as []:\n%s", raw)
	}
}

func TestManifestKeyOrder(t *testing.T) {
	_, raw := readManifest(t, buildPack(t, testKey(1)))
	last := -1
	for _, key := range []string{"schemaVersion", "tool", "createdAt", "profile", "summary", "inputs", "files", "publicKey"} {
		i := bytes.Index(raw, []byte("\n  \""+key+"\":"))
		if i <= last {
			t.Fatalf("key %q at %d, after %d:\n%s", key, i, last, raw)
		}
		last = i
	}
}

func TestPackDeterministic(t *testing.T) {
	key := testKey(1)
	a := buildPack(t, key)
	b := buildPack(t, key)
	for _, name := range packNames {
		x, err := os.ReadFile(filepath.Join(a, name))
		if err != nil {
			t.Fatal(err)
		}
		y, err := os.ReadFile(filepath.Join(b, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(x, y) {
			t.Errorf("%s differs between two builds", name)
		}
	}
}

func TestKeygenMode0600AndNoOverwrite(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "signer")
	if err := GenerateKey(prefix); err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(prefix + ".key")
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := os.ReadFile(prefix + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(keyPEM, []byte("-----BEGIN PRIVATE KEY-----\n")) || !bytes.HasPrefix(pubPEM, []byte("-----BEGIN PUBLIC KEY-----\n")) {
		t.Fatalf("PEM headers:\n%s\n%s", keyPEM, pubPEM)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(prefix + ".key")
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("key mode %v", info.Mode().Perm())
		}
	}
	priv, err := LoadPrivateKey(prefix + ".key")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := LoadPublicKey(prefix + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Equal(priv.Public()) {
		t.Fatal("public key does not match private key")
	}
	if err := GenerateKey(prefix); err == nil {
		t.Fatal("second keygen did not fail")
	}
	if b, _ := os.ReadFile(prefix + ".key"); !bytes.Equal(b, keyPEM) {
		t.Fatal("private key overwritten")
	}
	if b, _ := os.ReadFile(prefix + ".pub"); !bytes.Equal(b, pubPEM) {
		t.Fatal("public key overwritten")
	}
	onlyPub := filepath.Join(t.TempDir(), "half")
	if err := os.WriteFile(onlyPub+".pub", []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := GenerateKey(onlyPub); err == nil {
		t.Fatal("keygen with an existing .pub did not fail")
	}
	if _, err := os.Stat(onlyPub + ".key"); !os.IsNotExist(err) {
		t.Fatalf(".key written next to an existing .pub: %v", err)
	}
	onlyKey := filepath.Join(t.TempDir(), "half")
	if err := os.WriteFile(onlyKey+".key", []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := GenerateKey(onlyKey); err == nil {
		t.Fatal("keygen with an existing .key did not fail")
	}
	if b, _ := os.ReadFile(onlyKey + ".key"); string(b) != "old" {
		t.Fatal("existing .key overwritten")
	}
	if _, err := os.Stat(onlyKey + ".pub"); !os.IsNotExist(err) {
		t.Fatalf(".pub written next to an existing .key: %v", err)
	}
}

func TestLoadKeyErrors(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "k")
	if err := GenerateKey(prefix); err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(prefix + ".key")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateKey(prefix + ".pub"); err == nil {
		t.Fatal("public key loaded as private key")
	}
	_, err = LoadPublicKey(prefix + ".key")
	if err == nil {
		t.Fatal("private key loaded as public key")
	}
	body := strings.Split(strings.TrimSpace(string(keyPEM)), "\n")[1]
	if strings.Contains(err.Error(), body) || strings.Contains(err.Error(), "BEGIN") {
		t.Fatalf("error shows key material: %v", err)
	}
	garbage := filepath.Join(t.TempDir(), "garbage")
	if err := os.WriteFile(garbage, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateKey(garbage); err == nil {
		t.Fatal("garbage loaded as private key")
	}
	if _, err := LoadPublicKey(garbage); err == nil {
		t.Fatal("garbage loaded as public key")
	}
	if _, err := LoadPrivateKey(filepath.Join(t.TempDir(), "none")); err == nil {
		t.Fatal("missing file loaded")
	}
}

func TestVerifyOversizedFiles(t *testing.T) {
	key := testKey(1)
	dir := buildPack(t, key)
	sig := filepath.Join(dir, "manifest.sig")
	if err := os.WriteFile(sig, bytes.Repeat([]byte("A"), maxSignatureSize+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if res := mustVerify(t, dir, pubOf(key)); res.Signature != "invalid" || res.OK() {
		t.Fatalf("oversized sig: %+v", res)
	}
	if res := mustVerify(t, dir, nil); res.Signature != "not-checked" {
		t.Fatalf("oversized sig without key: %+v", res)
	}
	manifest := filepath.Join(dir, "manifest.json")
	raw, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(dir, nil); err != nil {
		t.Fatalf("control: %v", err)
	}
	big := append(raw, bytes.Repeat([]byte(" "), maxManifestSize+1-len(raw))...)
	if err := os.WriteFile(manifest, big, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(dir, nil); err == nil {
		t.Fatal("oversized manifest.json: no error")
	}
	if err := os.WriteFile(manifest, big[:maxManifestSize], 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(dir, nil); err != nil {
		t.Fatalf("manifest.json at the cap: %v", err)
	}
}
