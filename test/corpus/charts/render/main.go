package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"sigs.k8s.io/yaml"

	"github.com/sv222/kshield/internal/corpus"
)

type config struct {
	Charts  []chart  `json:"charts"`
	Samples []sample `json:"samples"`
}

type chart struct {
	Name       string    `json:"name"`
	Repo       string    `json:"repo"`
	Chart      string    `json:"chart"`
	Version    string    `json:"version"`
	AppVersion string    `json:"appVersion"`
	Namespace  string    `json:"namespace"`
	Variants   []variant `json:"variants"`
}

type variant struct {
	Name   string `json:"name"`
	Values string `json:"values"`
}

type sample struct {
	Name      string       `json:"name"`
	Repo      string       `json:"repo"`
	Tag       string       `json:"tag"`
	Namespace string       `json:"namespace"`
	Cases     []sampleCase `json:"cases"`
}

type sampleCase struct {
	Name    string   `json:"name"`
	Sources []string `json:"sources"`
}

func main() {
	dir := flag.String("dir", filepath.Join("test", "corpus", "charts"), "chart corpus directory")
	helm := flag.String("helm", "helm", "helm binary")
	flag.Parse()
	if err := run(*dir, *helm); err != nil {
		fmt.Fprintln(os.Stderr, "render:", err)
		os.Exit(1)
	}
}

func run(dir, helm string) error {
	cfg, err := load(filepath.Join(dir, "charts.yaml"))
	if err != nil {
		return err
	}
	home, err := os.MkdirTemp("", "kshield-helm-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(home) }()
	env := append(os.Environ(),
		"HELM_CONFIG_HOME="+filepath.Join(home, "config"),
		"HELM_CACHE_HOME="+filepath.Join(home, "cache"),
		"HELM_DATA_HOME="+filepath.Join(home, "data"),
	)
	for _, c := range cfg.Charts {
		if _, err := helmRun(helm, env, "repo", "add", c.Name, c.Repo); err != nil {
			return fmt.Errorf("chart %s: %w", c.Name, err)
		}
		for _, v := range c.Variants {
			out, err := helmRun(helm, env, "template", c.Name, c.Name+"/"+c.Chart,
				"--version", c.Version,
				"--namespace", c.Namespace,
				"-f", filepath.Join(dir, filepath.FromSlash(v.Values)))
			if err != nil {
				return fmt.Errorf("chart %s variant %s: %w", c.Name, v.Name, err)
			}
			if len(bytes.TrimSpace(out)) == 0 {
				return fmt.Errorf("chart %s variant %s: empty output", c.Name, v.Name)
			}
			path := filepath.Join(dir, c.Name, v.Name, corpus.RenderedFile)
			if err := writeAtomic(path, out); err != nil {
				return fmt.Errorf("chart %s variant %s: %w", c.Name, v.Name, err)
			}
			fmt.Println("rendered", filepath.ToSlash(path))
		}
	}
	for _, s := range cfg.Samples {
		for _, sc := range s.Cases {
			path := filepath.Join(dir, s.Name, sc.Name, corpus.RenderedFile)
			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("sample %s/%s: %w", s.Name, sc.Name, err)
			}
			if len(bytes.TrimSpace(data)) == 0 {
				return fmt.Errorf("sample %s/%s: empty %s", s.Name, sc.Name, corpus.RenderedFile)
			}
			fmt.Println("sample", filepath.ToSlash(path))
		}
	}
	return nil
}

func load(path string) (config, error) {
	var cfg config
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.UnmarshalStrict(data, &cfg); err != nil {
		return cfg, fmt.Errorf("%s: %w", path, err)
	}
	if len(cfg.Charts) == 0 {
		return cfg, fmt.Errorf("%s: no charts", path)
	}
	for _, c := range cfg.Charts {
		if c.Name == "" || c.Repo == "" || c.Chart == "" || c.Version == "" || c.Namespace == "" || len(c.Variants) == 0 {
			return cfg, fmt.Errorf("%s: chart %q: name, repo, chart, version, namespace and variants are required", path, c.Name)
		}
		for _, v := range c.Variants {
			if v.Name == "" || v.Values == "" {
				return cfg, fmt.Errorf("%s: chart %s: a variant needs name and values", path, c.Name)
			}
		}
	}
	for _, s := range cfg.Samples {
		if s.Name == "" || s.Repo == "" || s.Tag == "" || s.Namespace == "" || len(s.Cases) == 0 {
			return cfg, fmt.Errorf("%s: sample %q: name, repo, tag, namespace and cases are required", path, s.Name)
		}
		for _, sc := range s.Cases {
			if sc.Name == "" || len(sc.Sources) == 0 {
				return cfg, fmt.Errorf("%s: sample %s: a case needs name and sources", path, s.Name)
			}
			for _, src := range sc.Sources {
				if !strings.HasPrefix(src, "https://") || !strings.Contains(src, "/"+s.Tag+"/") {
					return cfg, fmt.Errorf("%s: sample %s/%s: source %q must be an https URL pinned to tag %s", path, s.Name, sc.Name, src, s.Tag)
				}
			}
		}
	}
	return cfg, nil
}

func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".rendered-*.yaml")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func helmRun(helm string, env []string, args ...string) ([]byte, error) {
	cmd := exec.Command(helm, args...)
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return nil, fmt.Errorf("helm %v: exit %d: %s", args, exit.ExitCode(), bytes.TrimSpace(stderr.Bytes()))
		}
		return nil, fmt.Errorf("helm %v: %w", args, err)
	}
	return stdout.Bytes(), nil
}
