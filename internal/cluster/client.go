package cluster

import (
	"fmt"
	"path/filepath"
	"strings"

	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type Client struct {
	Dynamic   dynamic.Interface
	Discovery discovery.DiscoveryInterface
	Core      kubernetes.Interface
	Context   string
	Server    string
}

func Connect(kubeconfig, context string) (*Client, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.ExplicitPath = kubeconfig
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{CurrentContext: context})
	fail := func(err error) error {
		return fmt.Errorf("kubeconfig %s context %q: %w", kubeconfigPaths(rules), context, err)
	}
	raw, err := cc.RawConfig()
	if err != nil {
		return nil, fail(err)
	}
	cfg, err := cc.ClientConfig()
	if err != nil {
		return nil, fail(err)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fail(err)
	}
	core, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fail(err)
	}
	name := context
	if name == "" {
		name = raw.CurrentContext
	}
	return &Client{Dynamic: dyn, Discovery: core.Discovery(), Core: core, Context: name, Server: cfg.Host}, nil
}

func kubeconfigPaths(rules *clientcmd.ClientConfigLoadingRules) string {
	if rules.ExplicitPath != "" {
		return rules.ExplicitPath
	}
	return strings.Join(rules.GetLoadingPrecedence(), string(filepath.ListSeparator))
}
