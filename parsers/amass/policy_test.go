package amass

import (
	"testing"

	"github.com/zero-day-ai/gibson-tool-runner/internal/policy"
	"github.com/zero-day-ai/gibson-tool-runner/internal/registry"
)

func TestPolicy_DropsConfigFlag(t *testing.T) {
	p, _ := registry.LookupArgsPolicy(toolName)
	_, dropped, err := policy.ApplyArgs([]string{"-config", "/tmp/attacker-config"}, p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dropped) != 1 || dropped[0].Flag != "-config" {
		t.Fatalf("expected -config dropped, got %+v", dropped)
	}
}

func TestPolicy_DropsOutputDir(t *testing.T) {
	p, _ := registry.LookupArgsPolicy(toolName)
	_, dropped, err := policy.ApplyArgs([]string{"-dir", "/etc/"}, p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dropped) != 1 || dropped[0].Flag != "-dir" {
		t.Fatalf("expected -dir dropped, got %+v", dropped)
	}
}
