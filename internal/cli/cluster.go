package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/sv222/kshield/internal/cluster"
	"github.com/sv222/kshield/internal/load"
	"github.com/sv222/kshield/internal/report"
	"github.com/sv222/kshield/internal/scan"
)

const clusterUsage = `usage: kshield scan cluster [--kubeconfig <file>] [--context <name>] [-n <ns> ...] [--profile dora] [--node-probe [--probe-namespace kube-system] [--probe-timeout 60s] [--probe-image <ref>]] [--format text|json|html|pdf|sarif] [--out <path>] [--fail-on fail|warn|never] [--deterministic] [--evidence <dir> [--sign-key <file>]]
--format pdf needs --out.
--probe-namespace, --probe-timeout and --probe-image need --node-probe.
--node-probe creates one short-lived pod per Linux node in the probe namespace. A node can take about 3 x timeout + 15 s.
`

const (
	flagProbeNamespace = "probe-namespace"
	flagProbeTimeout   = "probe-timeout"
	flagProbeImage     = "probe-image"
)

var connect = cluster.Connect

func interruptContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func scanCluster(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan cluster", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { write(stderr, clusterUsage) }
	var namespaces stringList
	fs.Var(&namespaces, "n", "namespace to scan (repeatable; default all namespaces)")
	fs.Var(&namespaces, "namespace", "namespace to scan (repeatable; default all namespaces)")
	kubeconfig := fs.String("kubeconfig", "", "kubeconfig file (default: KUBECONFIG or ~/.kube/config)")
	kubeContext := fs.String("context", "", "kubeconfig context (default: the current context)")
	profileID := fs.String("profile", defaultProfile, "profile id")
	format := fs.String("format", formatText, "report format")
	out := fs.String("out", "", "report file (default stdout)")
	failOn := fs.String("fail-on", failOnFail, "fail, warn or never")
	deterministic := fs.Bool("deterministic", false, "byte-identical output for the same cluster state")
	evidenceDir := fs.String("evidence", "", "write an evidence pack to this new or empty dir")
	signKey := fs.String("sign-key", "", "private key file to sign the evidence pack")
	nodeProbe := fs.Bool("node-probe", false, "create one short-lived pod per Linux node to read the active LSM list")
	probeNamespace := fs.String(flagProbeNamespace, cluster.DefaultProbeNamespace, "namespace of the probe pods")
	probeTimeout := fs.Duration(flagProbeTimeout, cluster.DefaultProbeTimeout, "limit for each of the create, the poll and the log read of one node; the worst case per node is about 3 x timeout + 15 s cleanup")
	probeImage := fs.String(flagProbeImage, cluster.ProbeImage, "probe pod image")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	probeFlagSet := false
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case flagProbeNamespace, flagProbeTimeout, flagProbeImage:
			probeFlagSet = true
		}
	})
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
	case probeFlagSet && !*nodeProbe:
		return usageError(stderr, "--%s, --%s and --%s need --node-probe", flagProbeNamespace, flagProbeTimeout, flagProbeImage)
	case *probeTimeout <= 0:
		return usageError(stderr, "--%s must be greater than 0", flagProbeTimeout)
	case *probeNamespace == "":
		return usageError(stderr, "--%s must not be empty", flagProbeNamespace)
	case *probeImage == "":
		return usageError(stderr, "--%s must not be empty", flagProbeImage)
	}

	if err := scan.CheckProfile(*profileID); err != nil {
		return usageError(stderr, "%v", err)
	}
	client, err := connect(*kubeconfig, *kubeContext)
	if err != nil {
		return usageError(stderr, "%v", err)
	}
	ctx, stop := interruptContext()
	defer stop()
	r, _, err := scan.Cluster(ctx, scan.ClusterOptions{
		ProfileID:     *profileID,
		Deterministic: *deterministic,
		Namespaces:    namespaces,
		NodeProbe:     *nodeProbe,
		Probe:         cluster.ProbeOptions{Namespace: *probeNamespace, Image: *probeImage, Timeout: *probeTimeout},
		Client:        client,
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

func rescanCluster(sr *report.Report, kubeconfig, kubeContext string, stderr io.Writer) ([]load.Object, int) {
	var namespaces []string
	if info := sr.Scan.Cluster; info != nil {
		namespaces = info.Namespaces
		if kubeContext == "" {
			kubeContext = info.Context
		}
	}
	client, err := connect(kubeconfig, kubeContext)
	if err != nil {
		return nil, usageError(stderr, "%v", err)
	}
	ctx, stop := interruptContext()
	defer stop()
	r, objs, err := scan.Cluster(ctx, scan.ClusterOptions{ProfileID: sr.Profile.ID, Deterministic: true, Namespaces: namespaces, Client: client})
	if err != nil {
		return nil, usageError(stderr, "%v", err)
	}
	if r.Summary.Incomplete {
		write(stderr, "kshield: the cluster re-scan is incomplete, so it cannot be matched to scan.json\n")
		for _, e := range r.Errors {
			write(stderr, "  "+e+"\n")
		}
		return nil, ExitIncomplete
	}
	return objs, ExitOK
}
