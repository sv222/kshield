package check

import (
	"slices"
	"strings"

	"github.com/sv222/kshield/internal/load"
)

const (
	groupKong             = "configuration.konghq.com"
	kindKongPlugin        = "KongPlugin"
	kindKongClusterPlugin = "KongClusterPlugin"
)

var kongPluginKeys = []string{"konghq.com/plugins", "plugins.konghq.com"}

var kongAuthPlugins = []string{
	"basic-auth", "hmac-auth", "jwt", "jwt-signer", "key-auth", "key-auth-enc", "ldap-auth", "ldap-auth-advanced",
	"mtls-auth", "oauth2", "oauth2-introspection", "openid-connect", "saml", "vault-auth",
}

type kongPlugin struct {
	obj     load.Object
	name    string
	plugin  string
	cluster bool
	auth    bool
}

func parseKongPlugin(o load.Object) kongPlugin {
	p := kongPlugin{
		obj:     o,
		name:    o.Ref.Name,
		plugin:  stringOf(dig(o.U.Object, "plugin")),
		cluster: o.Ref.Kind == kindKongClusterPlugin,
	}
	disabled, _ := dig(o.U.Object, "disabled").(bool)
	anonymous, _ := scalarString(dig(o.U.Object, "config", "anonymous"))
	p.auth = !disabled && anonymous == "" && slices.Contains(kongAuthPlugins, p.plugin)
	return p
}

func annotationsOf(o load.Object) map[string]string {
	return stringMapOf(dig(o.U.Object, "metadata", "annotations"))
}

func kongPluginNames(annotations map[string]string, refs []string) []string {
	names := slices.Clone(refs)
	for _, k := range kongPluginKeys {
		for _, n := range strings.Split(annotations[k], ",") {
			if n = strings.TrimSpace(n); n != "" {
				names = append(names, n)
			}
		}
	}
	return names
}

func (p kongPlugin) visibleFrom(namespace string) bool {
	return p.cluster || p.obj.Ref.Namespace == namespace
}

func kongAuth(in *Input, namespace string, annotations map[string]string, refs []string) (AuthEvidence, bool) {
	plugins := in.idx().kong
	for _, name := range kongPluginNames(annotations, refs) {
		for _, p := range plugins {
			if p.name == name && p.auth && p.visibleFrom(namespace) {
				return AuthEvidence{Source: AuthKong, Ref: p.obj.Ref, Detail: "runs the " + p.plugin + " authentication plugin"}, true
			}
		}
	}
	return AuthEvidence{}, false
}
