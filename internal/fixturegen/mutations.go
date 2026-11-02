package fixturegen

import (
	"fmt"
	"slices"

	"github.com/sv222/kshield/internal/corpus"
	"github.com/sv222/kshield/internal/report"
)

const (
	vllmObj    = "Deployment/" + Namespace + "/vllm"
	qdrantObj  = "Deployment/" + Namespace + "/qdrant"
	rayObj     = "RayCluster/" + Namespace + "/rc"
	vllmSvcObj = "Service/" + Namespace + "/vllm"
	denyObj    = "NetworkPolicy/" + Namespace + "/default-deny-egress"

	fail = report.VerdictFail
	warn = report.VerdictWarn
)

func Mutations() []Mutation {
	return []Mutation{
		{Name: "vllm-root-uid", Apply: vllmSecurity(func(sc map[string]any) error {
			sc["runAsUser"] = int64(0)
			return nil
		}), Expect: vllmContainerFinding("KS-WL-001", fail)},
		{Name: "vllm-privileged", Apply: vllmSecurity(func(sc map[string]any) error {
			sc["privileged"] = true
			return nil
		}), Expect: vllmContainerFinding("KS-WL-002", fail)},
		{Name: "vllm-no-drop", Apply: vllmSecurity(func(sc map[string]any) error {
			delete(sc, "capabilities")
			return nil
		}), Expect: vllmContainerFinding("KS-WL-003", fail)},
		{Name: "vllm-hostipc", Apply: vllmPod(func(pod map[string]any) error {
			pod["hostIPC"] = true
			return nil
		}), Expect: vllmPodFinding("KS-WL-004", fail)},
		{Name: "vllm-shm-hostpath", Conflicts: []string{"vllm-shm-nolimit"}, Apply: vllmShm(func(v map[string]any) error {
			delete(v, "emptyDir")
			v["hostPath"] = map[string]any{"path": "/dev/shm", "type": "Directory"}
			return nil
		}), Expect: vllmPodFinding("KS-WL-005", fail)},
		{Name: "vllm-shm-nolimit", Conflicts: []string{"vllm-shm-hostpath"}, Apply: vllmShm(func(v map[string]any) error {
			dir, err := child(v, "emptyDir")
			if err != nil {
				return err
			}
			delete(dir, "sizeLimit")
			return nil
		}), Expect: vllmPodFinding("KS-WL-006", warn)},
		{Name: "vllm-sharepid", Apply: vllmPod(func(pod map[string]any) error {
			pod["shareProcessNamespace"] = true
			return nil
		}), Expect: vllmPodFinding("KS-WL-007", fail)},
		{Name: "vllm-rw-root", Apply: vllmSecurity(func(sc map[string]any) error {
			sc["readOnlyRootFilesystem"] = false
			return nil
		}), Expect: vllmContainerFinding("KS-WL-008", warn)},
		{Name: "vllm-seccomp-unconfined", Apply: vllmSecurity(func(sc map[string]any) error {
			sc["seccompProfile"] = map[string]any{"type": "Unconfined"}
			return nil
		}), Expect: vllmContainerFinding("KS-WL-009", fail)},
		{Name: "vllm-automount", Apply: vllmPod(func(pod map[string]any) error {
			pod["automountServiceAccountToken"] = true
			return nil
		}), Expect: vllmPodFinding("KS-WL-010", fail)},
		{Name: "vllm-literal-token", Apply: vllmContainer(func(c map[string]any) error {
			return appendItem(c, "env", map[string]any{"name": "HF_TOKEN", "value": "hf_fixtureTokenNotReal0123456789"})
		}), Expect: vllmContainerFinding("KS-WL-011", fail)},
		{Name: "vllm-tag-image", Apply: vllmContainer(func(c map[string]any) error {
			c["image"] = "vllm/vllm-openai:v0.31.0"
			return nil
		}), Expect: vllmContainerFinding("KS-WL-012", warn)},
		{Name: "vllm-no-memlimit", Apply: vllmContainer(func(c map[string]any) error {
			limits, err := child(c, "resources", "limits")
			if err != nil {
				return err
			}
			delete(limits, "memory")
			return nil
		}), Expect: vllmContainerFinding("KS-WL-013", warn)},
		{Name: "ray-gpu-hostpath-nvidia", Apply: rayPod("gpu", func(pod map[string]any) error {
			return appendItem(pod, "volumes", map[string]any{"name": "nvidia0", "hostPath": map[string]any{"path": "/dev/nvidia0", "type": "CharDevice"}})
		}), Expect: []corpus.Expect{{Check: "KS-WL-014", Object: rayObj, Group: "gpu", Verdict: fail}}},
		{Name: "vllm-trust-remote-code", Apply: vllmContainer(func(c map[string]any) error {
			return appendItem(c, "args", "--trust-remote-code")
		}), Expect: vllmContainerFinding("KS-AI-002", fail)},
		{Name: "vllm-load-pt", Conflicts: []string{"vllm-load-unset"}, Apply: vllmContainer(func(c map[string]any) error {
			return setArg(c, "--load-format", "pt")
		}), Expect: vllmContainerFinding("KS-AI-003", fail)},
		{Name: "vllm-load-unset", Conflicts: []string{"vllm-load-pt"}, Apply: vllmContainer(func(c map[string]any) error {
			return removeArg(c, "--load-format")
		}), Expect: vllmContainerFinding("KS-AI-003", warn)},
		{Name: "vllm-nodeport-no-key", Apply: vllmNodePortNoKey, Expect: []corpus.Expect{
			{Check: "KS-AI-001", Object: vllmObj, Container: "vllm", Verdict: fail},
			{Check: "KS-AI-004", Object: vllmSvcObj, Verdict: fail},
		}},
		{Name: "ray-head-nodeport", Apply: func(objs []map[string]any) error {
			head, err := objectChild(objs, "RayCluster", "rc", "spec", "headGroupSpec")
			if err != nil {
				return err
			}
			head["serviceType"] = "NodePort"
			return nil
		}, Expect: []corpus.Expect{{Check: "KS-AI-005", Object: rayObj, Group: "head", Verdict: fail}}},
		{Name: "ray-gpu-no-tls", Apply: rayPod("gpu", func(pod map[string]any) error {
			c, err := named(pod, "containers", "ray-worker")
			if err != nil {
				return err
			}
			env, err := named(c, "env", "RAY_USE_TLS")
			if err != nil {
				return err
			}
			env["value"] = "0"
			return nil
		}), Expect: []corpus.Expect{{Check: "KS-AI-006", Object: rayObj, Group: "gpu", Container: "ray-worker", Verdict: fail}}},
		{Name: "qdrant-no-key", Apply: func(objs []map[string]any) error {
			c, err := podContainer(objs, "Deployment", "qdrant", "qdrant")
			if err != nil {
				return err
			}
			return removeNamed(c, "env", "QDRANT__SERVICE__API_KEY")
		}, Expect: []corpus.Expect{{Check: "KS-AI-008", Object: qdrantObj, Container: "qdrant", Verdict: fail}}},
		{Name: "netpol-removed", Conflicts: []string{"netpol-world"}, Apply: removeKind("NetworkPolicy"), Expect: perWorkload("KS-NET-001", fail)},
		{Name: "netpol-world", Conflicts: []string{"netpol-removed"}, Apply: func(objs []map[string]any) error {
			spec, err := objectChild(objs, "NetworkPolicy", "default-deny-egress", "spec")
			if err != nil {
				return err
			}
			spec["egress"] = []any{map[string]any{"to": []any{map[string]any{"ipBlock": map[string]any{"cidr": "0.0.0.0/0"}}}}}
			return nil
		}, Expect: []corpus.Expect{{Check: "KS-NET-002", Object: denyObj, Verdict: fail}}},
		{Name: "shell-guard-post", Apply: func(objs []map[string]any) error {
			return setGuardActions(objs, "kshield-shell-exec", "Post")
		}, Expect: perWorkload("KS-RT-001", warn)},
		{Name: "egress-guard-removed", Apply: removeObject("TracingPolicyNamespaced", "kshield-egress-connect"), Expect: perWorkload("KS-RT-002", fail)},
		{Name: "kyverno-audit", Apply: func(objs []map[string]any) error {
			spec, err := objectChild(objs, "Policy", "kshield-admission", "spec")
			if err != nil {
				return err
			}
			spec["validationFailureAction"] = "Audit"
			return nil
		}, Expect: perWorkload("KS-RT-003", warn)},
	}
}

func vllmContainerFinding(id, verdict string) []corpus.Expect {
	return []corpus.Expect{{Check: id, Object: vllmObj, Container: "vllm", Verdict: verdict}}
}

func vllmPodFinding(id, verdict string) []corpus.Expect {
	return []corpus.Expect{{Check: id, Object: vllmObj, Verdict: verdict}}
}

func perWorkload(id, verdict string) []corpus.Expect {
	return []corpus.Expect{
		{Check: id, Object: vllmObj, Verdict: verdict},
		{Check: id, Object: qdrantObj, Verdict: verdict},
		{Check: id, Object: rayObj, Group: "head", Verdict: verdict},
		{Check: id, Object: rayObj, Group: "cpu", Verdict: verdict},
		{Check: id, Object: rayObj, Group: "gpu", Verdict: verdict},
	}
}

func vllmNodePortNoKey(objs []map[string]any) error {
	c, err := podContainer(objs, "Deployment", "vllm", "vllm")
	if err != nil {
		return err
	}
	if err := removeArg(c, "--api-key"); err != nil {
		return err
	}
	if err := removeNamed(c, "env", "VLLM_API_KEY"); err != nil {
		return err
	}
	spec, err := objectChild(objs, "Service", "vllm", "spec")
	if err != nil {
		return err
	}
	spec["type"] = "NodePort"
	return nil
}

func setGuardActions(objs []map[string]any, name, action string) error {
	spec, err := objectChild(objs, "TracingPolicyNamespaced", name, "spec")
	if err != nil {
		return err
	}
	for _, kp := range items(spec["kprobes"]) {
		for _, sel := range items(kp["selectors"]) {
			for _, a := range items(sel["matchActions"]) {
				a["action"] = action
			}
		}
	}
	return nil
}

func vllmPod(f func(pod map[string]any) error) func([]map[string]any) error {
	return func(objs []map[string]any) error {
		pod, err := objectChild(objs, "Deployment", "vllm", "spec", "template", "spec")
		if err != nil {
			return err
		}
		return f(pod)
	}
}

func vllmContainer(f func(c map[string]any) error) func([]map[string]any) error {
	return func(objs []map[string]any) error {
		c, err := podContainer(objs, "Deployment", "vllm", "vllm")
		if err != nil {
			return err
		}
		return f(c)
	}
}

func vllmSecurity(f func(sc map[string]any) error) func([]map[string]any) error {
	return vllmContainer(func(c map[string]any) error {
		sc, err := child(c, "securityContext")
		if err != nil {
			return err
		}
		return f(sc)
	})
}

func vllmShm(f func(v map[string]any) error) func([]map[string]any) error {
	return vllmPod(func(pod map[string]any) error {
		v, err := named(pod, "volumes", "shm")
		if err != nil {
			return err
		}
		return f(v)
	})
}

func rayPod(group string, f func(pod map[string]any) error) func([]map[string]any) error {
	return func(objs []map[string]any) error {
		spec, err := objectChild(objs, "RayCluster", "rc", "spec")
		if err != nil {
			return err
		}
		for _, g := range items(spec["workerGroupSpecs"]) {
			if g["groupName"] != group {
				continue
			}
			pod, err := child(g, "template", "spec")
			if err != nil {
				return err
			}
			return f(pod)
		}
		return fmt.Errorf("RayCluster rc has no worker group %s", group)
	}
}

func removeKind(kind string) func([]map[string]any) error {
	return func(objs []map[string]any) error {
		n := 0
		for _, o := range objs {
			if o["kind"] == kind {
				clear(o)
				n++
			}
		}
		if n == 0 {
			return fmt.Errorf("no %s in the base", kind)
		}
		return nil
	}
}

func removeObject(kind, name string) func([]map[string]any) error {
	return func(objs []map[string]any) error {
		o, err := object(objs, kind, name)
		if err != nil {
			return err
		}
		clear(o)
		return nil
	}
}

func object(objs []map[string]any, kind, name string) (map[string]any, error) {
	for _, o := range objs {
		if o["kind"] != kind {
			continue
		}
		if meta, ok := o["metadata"].(map[string]any); ok && meta["name"] == name {
			return o, nil
		}
	}
	return nil, fmt.Errorf("no %s/%s in the base", kind, name)
}

func objectChild(objs []map[string]any, kind, name string, keys ...string) (map[string]any, error) {
	o, err := object(objs, kind, name)
	if err != nil {
		return nil, err
	}
	return child(o, keys...)
}

func podContainer(objs []map[string]any, kind, name, container string) (map[string]any, error) {
	pod, err := objectChild(objs, kind, name, "spec", "template", "spec")
	if err != nil {
		return nil, err
	}
	return named(pod, "containers", container)
}

func child(m map[string]any, keys ...string) (map[string]any, error) {
	cur := m
	for _, k := range keys {
		next, ok := cur[k].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("no map at key %s", k)
		}
		cur = next
	}
	return cur, nil
}

func items(v any) []map[string]any {
	list, _ := v.([]any)
	var out []map[string]any
	for _, e := range list {
		if m, ok := e.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func named(m map[string]any, listKey, name string) (map[string]any, error) {
	for _, e := range items(m[listKey]) {
		if e["name"] == name {
			return e, nil
		}
	}
	return nil, fmt.Errorf("no %s entry named %s", listKey, name)
}

func removeNamed(m map[string]any, listKey, name string) error {
	list, _ := m[listKey].([]any)
	i := slices.IndexFunc(list, func(e any) bool {
		em, ok := e.(map[string]any)
		return ok && em["name"] == name
	})
	if i < 0 {
		return fmt.Errorf("no %s entry named %s", listKey, name)
	}
	m[listKey] = slices.Delete(list, i, i+1)
	return nil
}

func appendItem(m map[string]any, listKey string, item any) error {
	list, ok := m[listKey].([]any)
	if !ok && m[listKey] != nil {
		return fmt.Errorf("%s is not a list", listKey)
	}
	m[listKey] = append(list, item)
	return nil
}

func argIndex(c map[string]any, flag string) ([]any, int, error) {
	args, _ := c["args"].([]any)
	i := slices.Index(args, any(flag))
	if i < 0 || i+1 >= len(args) {
		return nil, 0, fmt.Errorf("no %s with a value in args", flag)
	}
	return args, i, nil
}

func setArg(c map[string]any, flag, value string) error {
	args, i, err := argIndex(c, flag)
	if err != nil {
		return err
	}
	args[i+1] = value
	return nil
}

func removeArg(c map[string]any, flag string) error {
	args, i, err := argIndex(c, flag)
	if err != nil {
		return err
	}
	c["args"] = slices.Delete(args, i, i+2)
	return nil
}
