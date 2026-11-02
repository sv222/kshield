package cli

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sv222/kshield/internal/remediate"
	"github.com/sv222/kshield/internal/report"
	"github.com/sv222/kshield/internal/scan"
	"github.com/sv222/kshield/internal/version"
)

const (
	ExitOK         = 0
	ExitFindings   = 1
	ExitUsage      = 2
	ExitIncomplete = 3
)

const (
	formatText  = "text"
	formatJSON  = "json"
	formatHTML  = "html"
	formatPDF   = "pdf"
	formatSARIF = "sarif"
	failOnFail  = "fail"
	failOnWarn  = "warn"
	failOnNever = "never"

	defaultNamespace = "default"
	defaultProfile   = "dora"
)

const usage = `usage:
  kshield scan manifest -f <file|dir|-> [-f ...] [-n <ns>] [--profile dora] [--format text|json|html|pdf|sarif] [--out <path>] [--fail-on fail|warn|never] [--deterministic] [--evidence <dir> [--sign-key <file>]]
  kshield scan cluster [--kubeconfig <file>] [--context <name>] [-n <ns> ...] [--profile dora] [--node-probe [--probe-namespace kube-system] [--probe-timeout 60s] [--probe-image <ref>]] [--format text|json|html|pdf|sarif] [--out <path>] [--fail-on fail|warn|never] [--deterministic] [--evidence <dir> [--sign-key <file>]]
  kshield remediate --from <scan.json> [-f <file|dir|-> ...] [-n <ns>] [--kubeconfig <file>] [--context <name>] [--mode audit|enforce] [--allow-fqdn <name> ...] [--allow-cidr <cidr> ...] [--out <dir>]
  kshield checks list [--profile dora] [--format text|json]
  kshield checks explain <check-id|display-id> [--profile dora]
  kshield profiles list [--format text|json]
  kshield evidence verify <dir> [--pub-key <file>]
  kshield evidence keygen --out <prefix>
  kshield version

--format pdf needs --out.
--node-probe creates one short-lived pod per Linux node in the probe namespace.

exit codes:
  0  nothing at or above --fail-on
  1  findings at or above --fail-on
  2  usage or input error
  3  scan incomplete
`

const manifestUsage = `usage: kshield scan manifest -f <file|dir|-> [-f ...] [-n <ns>] [--profile dora] [--format text|json|html|pdf|sarif] [--out <path>] [--fail-on fail|warn|never] [--deterministic] [--evidence <dir> [--sign-key <file>]]
--format pdf needs --out.
`

var writers = map[string]func(io.Writer, *report.Report) error{
	formatText:  report.WriteText,
	formatJSON:  report.WriteJSON,
	formatHTML:  report.WriteHTML,
	formatPDF:   report.WritePDF,
	formatSARIF: report.WriteSARIF,
}

func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		write(stderr, usage)
		return ExitUsage
	}
	switch args[0] {
	case "help", "-h", "--help":
		write(stdout, usage)
		return ExitOK
	case "version":
		write(stdout, version.String()+"\n")
		return ExitOK
	case "scan":
		return runScan(args[1:], stdin, stdout, stderr)
	case "remediate":
		return runRemediate(args[1:], stdin, stdout, stderr)
	case "checks":
		return runChecks(args[1:], stdout, stderr)
	case "profiles":
		return runProfiles(args[1:], stdout, stderr)
	case "evidence":
		return runEvidence(args[1:], stdout, stderr)
	default:
		write(stderr, fmt.Sprintf("kshield: unknown command %q\n\n%s", args[0], usage))
		return ExitUsage
	}
}

func runScan(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		write(stderr, "kshield: scan: missing subcommand (manifest or cluster)\n\n"+usage)
		return ExitUsage
	}
	switch args[0] {
	case "manifest":
		return scanManifest(args[1:], stdin, stdout, stderr)
	case "cluster":
		return scanCluster(args[1:], stdout, stderr)
	}
	write(stderr, fmt.Sprintf("kshield: scan: unknown subcommand %q\n\n%s", args[0], usage))
	return ExitUsage
}

type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(v string) error {
	if v == "" {
		return errors.New("empty value")
	}
	*l = append(*l, v)
	return nil
}

func scanManifest(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan manifest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { write(stderr, manifestUsage) }
	var inputs stringList
	namespace := defaultNamespace
	fs.Var(&inputs, "f", "manifest file, directory or - for stdin (repeatable)")
	fs.StringVar(&namespace, "n", defaultNamespace, "namespace for objects without one")
	fs.StringVar(&namespace, "namespace", defaultNamespace, "namespace for objects without one")
	profileID := fs.String("profile", defaultProfile, "profile id")
	format := fs.String("format", formatText, "report format")
	out := fs.String("out", "", "report file (default stdout)")
	failOn := fs.String("fail-on", failOnFail, "fail, warn or never")
	deterministic := fs.Bool("deterministic", false, "byte-identical output for the same input")
	evidenceDir := fs.String("evidence", "", "write an evidence pack to this new or empty dir")
	signKey := fs.String("sign-key", "", "private key file to sign the evidence pack")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	switch {
	case fs.NArg() > 0:
		return usageError(stderr, "unexpected argument %q", fs.Arg(0))
	case writers[*format] == nil:
		return usageError(stderr, "unknown format %q (text, json, html, pdf or sarif)", *format)
	case *format == formatPDF && *out == "":
		return usageError(stderr, "--format pdf needs --out")
	case *failOn != failOnFail && *failOn != failOnWarn && *failOn != failOnNever:
		return usageError(stderr, "unknown --fail-on value %q (fail, warn or never)", *failOn)
	case *signKey != "" && *evidenceDir == "":
		return usageError(stderr, "--sign-key needs --evidence")
	case *out != "" && *evidenceDir != "" && insideDir(*out, *evidenceDir):
		return usageError(stderr, "--out %s must not be inside the --evidence dir %s", *out, *evidenceDir)
	case len(inputs) == 0:
		return usageError(stderr, "at least one -f is required")
	}

	r, err := scan.Manifest(scan.Options{
		Inputs:        inputs,
		Namespace:     namespace,
		ProfileID:     *profileID,
		Deterministic: *deterministic,
		Stdin:         stdin,
	})
	if err != nil {
		return usageError(stderr, "%v", err)
	}
	var buf bytes.Buffer
	if err := writers[*format](&buf, r); err != nil {
		return usageError(stderr, "%v", err)
	}
	if *evidenceDir != "" {
		if err := writeEvidence(*evidenceDir, *signKey, r); err != nil {
			return usageError(stderr, "%v", err)
		}
	}
	if *out == "" {
		if _, err := stdout.Write(buf.Bytes()); err != nil {
			return usageError(stderr, "%v", err)
		}
	} else if err := os.WriteFile(*out, buf.Bytes(), 0o644); err != nil {
		return usageError(stderr, "%v", err)
	}
	return ExitCode(r, *failOn)
}

func ExitCode(r *report.Report, failOn string) int {
	switch {
	case r.Summary.Incomplete:
		return ExitIncomplete
	case failOn == failOnNever:
		return ExitOK
	case r.Summary.Fail > 0, failOn == failOnWarn && r.Summary.Warn > 0:
		return ExitFindings
	}
	return ExitOK
}

func usageError(stderr io.Writer, format string, a ...any) int {
	write(stderr, "kshield: "+fmt.Sprintf(format, a...)+"\n")
	return ExitUsage
}

func write(w io.Writer, s string) {
	_, _ = io.WriteString(w, s)
}

const (
	remediateUsage = `usage: kshield remediate --from <scan.json> [-f <file|dir|-> ...] [-n <ns>] [--kubeconfig <file>] [--context <name>] [--mode audit|enforce] [--allow-fqdn <name> ...] [--allow-cidr <cidr> ...] [--out <dir>]
`
	modeAudit        = "audit"
	modeEnforce      = "enforce"
	defaultBundleDir = "kshield-remediation"
)

func runRemediate(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("remediate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { write(stderr, remediateUsage) }
	var inputs, fqdns, cidrs stringList
	var namespace string
	from := fs.String("from", "", "scan.json of a manifest or cluster scan")
	kubeconfig := fs.String("kubeconfig", "", "kubeconfig file for a cluster scan.json (default: KUBECONFIG or ~/.kube/config)")
	kubeContext := fs.String("context", "", "kubeconfig context for a cluster scan.json (default: the context in scan.json)")
	fs.Var(&inputs, "f", "manifest file, directory or - for stdin (repeatable; default: the scan inputs)")
	fs.StringVar(&namespace, "n", "", "namespace for objects without one (default: the scan namespace)")
	fs.StringVar(&namespace, "namespace", "", "namespace for objects without one (default: the scan namespace)")
	mode := fs.String("mode", modeAudit, "audit or enforce")
	fs.Var(&fqdns, "allow-fqdn", "egress DNS name to allow (repeatable)")
	fs.Var(&cidrs, "allow-cidr", "egress CIDR to allow (repeatable)")
	out := fs.String("out", defaultBundleDir, "output directory (missing or empty)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	switch {
	case fs.NArg() > 0:
		return usageError(stderr, "unexpected argument %q", fs.Arg(0))
	case *from == "":
		return usageError(stderr, "--from <scan.json> is required")
	case *mode != modeAudit && *mode != modeEnforce:
		return usageError(stderr, "unknown --mode value %q (audit or enforce)", *mode)
	case *out == "":
		return usageError(stderr, "--out must not be empty")
	}
	data, err := os.ReadFile(*from)
	if err != nil {
		return usageError(stderr, "%v", err)
	}
	opt := remediate.Options{
		ScanJSON:  data,
		Inputs:    inputs,
		Namespace: namespace,
		Mode:      *mode,
		AllowFQDN: fqdns,
		AllowCIDR: cidrs,
		Stdin:     stdin,
	}
	sr, err := remediate.ReadScan(data)
	switch {
	case errors.Is(err, remediate.ErrIncomplete):
		write(stderr, "kshield: "+err.Error()+"\n")
		return ExitIncomplete
	case err != nil:
		return usageError(stderr, "%v", err)
	case sr.Scan.Mode != report.ModeCluster && (*kubeconfig != "" || *kubeContext != ""):
		return usageError(stderr, "--kubeconfig and --context need the scan.json of a cluster scan")
	case sr.Scan.Mode == report.ModeCluster && len(inputs) > 0:
		return usageError(stderr, "%v", remediate.ErrClusterFiles)
	case sr.Scan.Mode == report.ModeCluster && namespace != "":
		return usageError(stderr, "-n does not apply to a cluster scan.json")
	case sr.Scan.Mode == report.ModeCluster:
		var code int
		if opt.Objects, code = rescanCluster(sr, *kubeconfig, *kubeContext, stderr); code != ExitOK {
			return code
		}
	}
	b, err := remediate.Run(opt)
	if errors.Is(err, remediate.ErrIncomplete) {
		write(stderr, "kshield: "+err.Error()+"\n")
		return ExitIncomplete
	}
	if err != nil {
		return usageError(stderr, "%v", err)
	}
	if err := remediate.Write(*out, b); err != nil {
		return usageError(stderr, "%v", err)
	}
	names := make([]string, 0, len(b.Files))
	for name := range b.Files {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		write(stdout, path.Join(filepath.ToSlash(*out), name)+"\n")
	}
	return ExitOK
}
