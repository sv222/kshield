//go:build kind

package kind

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/sv222/kshield/internal/evidence"
	"github.com/sv222/kshield/internal/htmlcheck"
)

func TestKindEvidence(t *testing.T) {
	ns := tempNamespace(t, nil)
	applyToxic(t, ns)

	prefix := filepath.Join(t.TempDir(), "signer")
	if err := evidence.GenerateKey(prefix); err != nil {
		t.Fatal(err)
	}
	pub, err := evidence.LoadPublicKey(prefix + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "pack")
	res := runScan(t, kubeconfig(t), "-n", ns, "--deterministic", "--evidence", dir, "--sign-key", prefix+".key")
	wantExit(t, res, 1)

	t.Run("a signed pack verifies", func(t *testing.T) {
		v, err := evidence.Verify(dir, pub)
		if err != nil {
			t.Fatal(err)
		}
		if !v.OK() || v.Signature != evidence.SignatureValid {
			t.Fatalf("verify %+v, want OK and signature %q", v, evidence.SignatureValid)
		}
	})

	t.Run("b control tampered copy fails", func(t *testing.T) {
		tampered := copyDir(t, dir, func(name string, data []byte) []byte {
			if name == "report.json" {
				data[len(data)/2] ^= 0x01
			}
			return data
		})
		v, err := evidence.Verify(tampered, pub)
		if err != nil {
			t.Fatal(err)
		}
		if v.OK() || !slices.Equal(v.Changed, []string{"report.json"}) || len(v.Missing) > 0 || len(v.Extra) > 0 {
			t.Fatalf("verify %+v, want not OK with only Changed [report.json]", v)
		}
	})

	t.Run("c HTML makes no network request", func(t *testing.T) {
		page := readFileT(t, filepath.Join(dir, "report.html"))
		if v := htmlcheck.NoNetwork(page); len(v) > 0 {
			t.Fatalf("report.html: %v", v)
		}
	})
}
