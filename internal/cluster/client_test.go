package cluster

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testKubeconfig = `apiVersion: v1
kind: Config
current-context: one
clusters:
- name: c1
  cluster:
    server: https://127.0.0.1:6443
- name: c2
  cluster:
    server: https://127.0.0.2:6443
users:
- name: u
  user:
    token: tok-s3cret-value
contexts:
- name: one
  context:
    cluster: c1
    user: u
- name: two
  context:
    cluster: c2
    user: u
`

func writeKubeconfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(path, []byte(testKubeconfig), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestConnect(t *testing.T) {
	path := writeKubeconfig(t)
	c, err := Connect(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if c.Context != "one" || c.Server != "https://127.0.0.1:6443" || c.Dynamic == nil || c.Discovery == nil || c.Core == nil {
		t.Fatalf("client %+v", c)
	}
	c, err = Connect(path, "two")
	if err != nil {
		t.Fatal(err)
	}
	if c.Context != "two" || c.Server != "https://127.0.0.2:6443" {
		t.Fatalf("context %q server %q", c.Context, c.Server)
	}
}

func TestConnectKubeconfigEnv(t *testing.T) {
	t.Setenv("KUBECONFIG", writeKubeconfig(t))
	c, err := Connect("", "two")
	if err != nil {
		t.Fatal(err)
	}
	if c.Context != "two" {
		t.Fatalf("context %q", c.Context)
	}
}

func TestConnectErrors(t *testing.T) {
	path := writeKubeconfig(t)
	missing := filepath.Join(t.TempDir(), "none")
	for _, tc := range []struct{ kubeconfig, context, want string }{
		{path, "three", `kubeconfig ` + path + ` context "three"`},
		{missing, "", `kubeconfig ` + missing + ` context ""`},
	} {
		_, err := Connect(tc.kubeconfig, tc.context)
		if err == nil {
			t.Fatalf("%s %s: no error", tc.kubeconfig, tc.context)
		}
		if !strings.HasPrefix(err.Error(), tc.want+": ") {
			t.Errorf("error %q, want prefix %q", err, tc.want)
		}
		if strings.Contains(err.Error(), "s3cret") {
			t.Errorf("error leaks the token: %q", err)
		}
	}
}
