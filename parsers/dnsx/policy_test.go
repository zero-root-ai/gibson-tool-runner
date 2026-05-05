package dnsx

import (
	"testing"

	"github.com/zero-day-ai/gibson-tool-runner/internal/policy"
	"github.com/zero-day-ai/gibson-tool-runner/internal/registry"
)

func TestPolicy_DropsOutputFlag(t *testing.T) {
	p, _ := registry.LookupArgsPolicy(toolName)
	_, dropped, err := policy.ApplyArgs([]string{"-o", "/etc/passwd"}, p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dropped) != 1 || dropped[0].Flag != "-o" {
		t.Fatalf("expected -o dropped, got %+v", dropped)
	}
}

func TestPolicy_AllowsRecordSelectors(t *testing.T) {
	p, _ := registry.LookupArgsPolicy(toolName)
	out, _, err := policy.ApplyArgs([]string{"-cname", "-mx", "-txt"}, p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("expected 3 args, got %v", out)
	}
}
