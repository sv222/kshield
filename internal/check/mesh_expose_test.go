package check

import (
	"strings"
	"testing"
)

func TestMeshProtectedExposureIsInfo(t *testing.T) {
	policy := meshDoc(kindAuthorizationPolicy, "svc", serviceTarget+principalRule)
	doc := deployment(meshOllamaSpec) + svcDoc("ai", "svc", "LoadBalancer", "app: vllm", "port: 11434")
	r := runWL(t, "KS-AI-007", doc+policy)
	if !r.Applicable || len(r.Findings) != 1 {
		t.Fatalf("result %+v", r)
	}
	f := r.Findings[0]
	if f.Strength != Declared || !strings.Contains(f.Message, "AuthorizationPolicy ai/svc") || f.Object.String() != "Service/ai/svc" {
		t.Errorf("finding %+v", f)
	}
	open := runWL(t, "KS-AI-007", doc)
	if len(open.Findings) != 1 || open.Findings[0].Strength != Violation {
		t.Errorf("unprotected %+v", open)
	}
}

func TestMeshProtectedIngressIsInfo(t *testing.T) {
	policy := meshDoc(kindAuthorizationPolicy, "svc", serviceTarget+principalRule)
	doc := deployment(vllmContainerSpec) + svcDoc("ai", "svc", "", "app: vllm", "port: 80") + ingressDoc(ingressAPIVersion, "ai", "web", "", ruleSpec("svc"))
	r := runWL(t, "KS-AI-004", doc+policy)
	if len(r.Findings) != 1 || r.Findings[0].Strength != Declared || r.Findings[0].Object.String() != "Ingress/ai/web" {
		t.Fatalf("findings %+v", r.Findings)
	}
	open := runWL(t, "KS-AI-004", doc)
	if len(open.Findings) != 1 || open.Findings[0].Strength != Violation {
		t.Errorf("unprotected %+v", open.Findings)
	}
}
