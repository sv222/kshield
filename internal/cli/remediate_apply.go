package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"k8s.io/client-go/dynamic"

	"github.com/sv222/kshield/internal/remediate"
)

const applyTimeout = 5 * time.Minute

var stdinIsTerminal = func(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

type applyFlags struct {
	apply       bool
	patches     bool
	yes         bool
	dryRun      bool
	force       bool
	skipMissing bool
}

func applyBundle(b *remediate.Bundle, kubeconfig, kubeContext string, f applyFlags, stdin io.Reader, stdout, stderr io.Writer) int {
	objs, err := remediate.PlanApply(b, f.patches)
	if err != nil {
		return usageError(stderr, "%v", err)
	}
	if len(objs) == 0 {
		write(stdout, "kshield: nothing to apply: the bundle has no policies"+noPatchesNote(f)+"\n")
		return ExitOK
	}
	client, err := connect(kubeconfig, kubeContext)
	if err != nil {
		return usageError(stderr, "%v", err)
	}
	write(stdout, fmt.Sprintf("cluster: context %q, server %s\n", client.Context, client.Server))
	found, missing, err := remediate.Resolve(client.Discovery, objs)
	if err != nil {
		return usageError(stderr, "%v", err)
	}
	if len(missing) > 0 && !f.skipMissing {
		return refuseMissing(missing, stderr)
	}
	for _, m := range missing {
		write(stdout, fmt.Sprintf("skipping %d object(s): %s\n", len(m.Objects), missingLine(m)))
	}
	if len(found) == 0 {
		write(stdout, "kshield: nothing to apply: the cluster serves none of the kinds in the bundle\n")
		return ExitOK
	}
	verb := "apply"
	if f.dryRun {
		verb = "dry run"
	}
	for _, o := range found {
		write(stdout, fmt.Sprintf("%s %s (%s)\n", verb, o.Label(), o.Role))
	}
	write(stdout, patchesNote(f))
	ctx, stop := interruptContext()
	defer stop()
	if !f.dryRun {
		if err := runApply(ctx, client.Dynamic, found, f, true, io.Discard); err != nil {
			write(stderr, "kshield: the server-side dry run failed, nothing was applied: "+err.Error()+"\n")
			return ExitApplyFailed
		}
		if !f.yes {
			if code := confirm(len(found), client.Context, stdin, stdout, stderr); code != ExitOK {
				return code
			}
		}
	}
	if err := runApply(ctx, client.Dynamic, found, f, f.dryRun, stdout); err != nil {
		write(stderr, "kshield: "+err.Error()+"\n")
		return ExitApplyFailed
	}
	return ExitOK
}

func runApply(ctx context.Context, client dynamic.Interface, objs []remediate.ApplyObject, f applyFlags, dryRun bool, out io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, applyTimeout)
	defer cancel()
	return remediate.RunApply(ctx, client, objs, remediate.ApplyOptions{ForceConflicts: f.force, DryRun: dryRun}, out)
}

func noPatchesNote(f applyFlags) string {
	if f.patches {
		return " and no patched workloads"
	}
	return ""
}

func patchesNote(f applyFlags) string {
	if f.patches {
		return "workload patches are applied: the pods of the patched workloads restart\n"
	}
	return "workload patches are not applied (they restart pods): add --apply-patches to include them\n"
}

func missingLine(m remediate.MissingKind) string {
	line := m.APIVersion + " " + m.Kind + " is not served by the cluster"
	if m.Product != "" {
		line += " (is " + m.Product + " installed?)"
	}
	return line
}

func refuseMissing(missing []remediate.MissingKind, stderr io.Writer) int {
	write(stderr, "kshield: refusing to apply: the cluster does not serve these kinds:\n")
	for _, m := range missing {
		write(stderr, fmt.Sprintf("  - %s: %d object(s)\n", missingLine(m), len(m.Objects)))
	}
	write(stderr, "install the missing components, or pass --skip-missing-crds to skip their objects\n")
	return ExitUsage
}

func confirm(n int, contextName string, stdin io.Reader, stdout, stderr io.Writer) int {
	if !stdinIsTerminal(stdin) {
		return usageError(stderr, "refusing to apply without confirmation: stdin is not a terminal, pass --yes to apply")
	}
	write(stdout, fmt.Sprintf("Apply %d objects to context %q? [y/N] ", n, contextName))
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return usageError(stderr, "%v", err)
	}
	if answer := strings.ToLower(strings.TrimSpace(line)); answer != "y" && answer != "yes" {
		write(stderr, "kshield: aborted, nothing was applied\n")
		return ExitUsage
	}
	return ExitOK
}
