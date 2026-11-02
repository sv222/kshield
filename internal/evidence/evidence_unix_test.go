//go:build unix

package evidence

import (
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"
)

func verifyWithin(t *testing.T, dir string, pub []byte) (Result, error) {
	t.Helper()
	type out struct {
		res Result
		err error
	}
	done := make(chan out, 1)
	go func() {
		res, err := Verify(dir, pub)
		done <- out{res, err}
	}()
	select {
	case o := <-done:
		return o.res, o.err
	case <-time.After(10 * time.Second):
		t.Fatal("Verify did not return within 10s")
	}
	return Result{}, nil
}

func replaceWithFIFO(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o644); err != nil {
		t.Fatal(err)
	}
}

func replaceWithSymlink(t *testing.T, path, target string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
}

func copyOut(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), filepath.Base(path))
	if err := os.WriteFile(dst, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return dst
}

func TestVerifyFIFOManifest(t *testing.T) {
	dir := buildPack(t, nil)
	replaceWithFIFO(t, filepath.Join(dir, "manifest.json"))
	if _, err := verifyWithin(t, dir, nil); err == nil {
		t.Fatal("FIFO manifest.json: no error")
	}
}

func TestVerifyFIFOSignature(t *testing.T) {
	key := testKey(1)
	dir := buildPack(t, key)
	replaceWithFIFO(t, filepath.Join(dir, "manifest.sig"))
	res, err := verifyWithin(t, dir, pubOf(key))
	if err != nil || res.Signature != "invalid" || res.OK() {
		t.Fatalf("FIFO sig with key: %+v %v", res, err)
	}
	res, err = verifyWithin(t, dir, nil)
	if err != nil || res.Signature != "not-checked" {
		t.Fatalf("FIFO sig without key: %+v %v", res, err)
	}
}

func TestVerifyFIFOReport(t *testing.T) {
	dir := buildPack(t, nil)
	replaceWithFIFO(t, filepath.Join(dir, "report.txt"))
	res, err := verifyWithin(t, dir, nil)
	if err != nil || !slices.Equal(res.Changed, []string{"report.txt"}) {
		t.Fatalf("FIFO report: %+v %v", res, err)
	}
}

func TestVerifySymlinks(t *testing.T) {
	key := testKey(1)
	dir := buildPack(t, key)
	if res, err := verifyWithin(t, dir, pubOf(key)); err != nil || res.Signature != "valid" {
		t.Fatalf("control: %+v %v", res, err)
	}
	sig := filepath.Join(dir, "manifest.sig")
	replaceWithSymlink(t, sig, copyOut(t, sig))
	if res, err := verifyWithin(t, dir, pubOf(key)); err != nil || res.Signature != "invalid" || res.OK() {
		t.Fatalf("symlink sig: %+v %v", res, err)
	}
	html := filepath.Join(dir, "report.html")
	replaceWithSymlink(t, html, copyOut(t, html))
	if res, err := verifyWithin(t, dir, nil); err != nil || !slices.Equal(res.Changed, []string{"report.html"}) {
		t.Fatalf("symlink report: %+v %v", res, err)
	}
	manifest := filepath.Join(dir, "manifest.json")
	replaceWithSymlink(t, manifest, copyOut(t, manifest))
	if _, err := verifyWithin(t, dir, nil); err == nil {
		t.Fatal("symlink manifest.json: no error")
	}
}

func TestVerifyManifestDevZero(t *testing.T) {
	if _, err := os.Stat("/dev/zero"); err != nil {
		t.Skip("no /dev/zero")
	}
	dir := buildPack(t, nil)
	replaceWithSymlink(t, filepath.Join(dir, "manifest.json"), "/dev/zero")
	if _, err := verifyWithin(t, dir, nil); err == nil {
		t.Fatal("manifest.json -> /dev/zero: no error")
	}
}
