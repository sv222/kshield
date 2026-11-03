package load

var clusterScoped = map[string]struct{}{
	"Namespace":                        {},
	"Node":                             {},
	"PersistentVolume":                 {},
	"StorageClass":                     {},
	"ClusterRole":                      {},
	"ClusterRoleBinding":               {},
	"CustomResourceDefinition":         {},
	"ValidatingWebhookConfiguration":   {},
	"MutatingWebhookConfiguration":     {},
	"ValidatingAdmissionPolicy":        {},
	"ValidatingAdmissionPolicyBinding": {},
	"PriorityClass":                    {},
	"IngressClass":                     {},
	"RuntimeClass":                     {},
	"CSIDriver":                        {},
	"APIService":                       {},
	"ClusterPolicy":                    {},
	"ClusterCleanupPolicy":             {},
	"TracingPolicy":                    {},
	"CiliumClusterwideNetworkPolicy":   {},
	"ClusterServingRuntime":            {},
	"ClusterStorageContainer":          {},
	"ClusterIssuer":                    {},
}

func IsClusterScoped(kind string) bool {
	_, ok := clusterScoped[kind]
	return ok
}
