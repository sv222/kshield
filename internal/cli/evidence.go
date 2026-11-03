package cli

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sv222/kshield/internal/evidence"
	"github.com/sv222/kshield/internal/report"
)

const evidenceUsage = `usage:
  kshield evidence verify <dir> [--pub-key <file>]
  kshield evidence keygen --out <prefix>

verify exit codes: 0 verified, 1 verification failed, 2 usage or input error.
`

func runEvidence(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		write(stderr, "kshield: evidence: missing subcommand (verify or keygen)\n\n"+evidenceUsage)
		return ExitUsage
	}
	switch args[0] {
	case "verify":
		return evidenceVerify(args[1:], stdout, stderr)
	case "keygen":
		return evidenceKeygen(args[1:], stdout, stderr)
	}
	write(stderr, fmt.Sprintf("kshield: evidence: unknown subcommand %q\n\n%s", args[0], evidenceUsage))
	return ExitUsage
}

func writeEvidence(dir, keyPath string, r *report.Report) error {
	var key ed25519.PrivateKey
	if keyPath != "" {
		var err error
		if key, err = evidence.LoadPrivateKey(keyPath); err != nil {
			return err
		}
	}
	return evidence.Build(dir, r, key)
}

func insideDir(path, dir string) bool {
	p, err := filepath.Abs(path)
	if err != nil {
		return true
	}
	d, err := filepath.Abs(dir)
	if err != nil {
		return true
	}
	rel, err := filepath.Rel(d, p)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func evidenceVerify(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("evidence verify", evidenceUsage, stderr)
	pubPath := fs.String("pub-key", "", "public key file (PEM)")
	positional, code, ok := parseArgs(fs, args)
	switch {
	case !ok:
		return code
	case len(positional) == 0:
		return usageError(stderr, "evidence verify needs a pack dir")
	case len(positional) > 1:
		return usageError(stderr, "unexpected argument %q", positional[1])
	}
	var pub ed25519.PublicKey
	if *pubPath != "" {
		var err error
		if pub, err = evidence.LoadPublicKey(*pubPath); err != nil {
			return usageError(stderr, "%v", err)
		}
	}
	res, err := evidence.Verify(positional[0], pub)
	if err != nil {
		return usageError(stderr, "%v", err)
	}
	var b strings.Builder
	for _, group := range []struct {
		label string
		names []string
	}{
		{"missing", res.Missing},
		{"changed", res.Changed},
		{"extra", res.Extra},
	} {
		for _, name := range group.names {
			b.WriteString(group.label + ": " + showName(name) + "\n")
		}
	}
	b.WriteString("signature: " + res.Signature + "\n")
	verified := res.OK() && (pub == nil || res.Signature == evidence.SignatureValid)
	if verified {
		b.WriteString("evidence: OK\n")
	} else {
		b.WriteString("evidence: FAILED\n")
	}
	write(stdout, b.String())
	if !verified {
		return ExitFindings
	}
	return ExitOK
}

func showName(name string) string {
	if q := strconv.Quote(name); q != `"`+name+`"` {
		return q
	}
	return name
}

func evidenceKeygen(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("evidence keygen", evidenceUsage, stderr)
	prefix := fs.String("out", "", "path prefix for <prefix>.key and <prefix>.pub")
	positional, code, ok := parseArgs(fs, args)
	switch {
	case !ok:
		return code
	case len(positional) > 0:
		return usageError(stderr, "unexpected argument %q", positional[0])
	case *prefix == "":
		return usageError(stderr, "evidence keygen needs --out <prefix>")
	}
	if err := evidence.GenerateKey(*prefix); err != nil {
		return usageError(stderr, "%v", err)
	}
	write(stdout, "private key: "+*prefix+".key\npublic key: "+*prefix+".pub\n")
	return ExitOK
}
