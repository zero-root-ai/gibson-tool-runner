package nuclei

import (
	"testing"

	"github.com/zero-day-ai/gibson-tool-runner/internal/policy"
	"github.com/zero-day-ai/gibson-tool-runner/internal/registry"
)

// TestPolicy_DropsTemplatesFlag asserts that caller-supplied -t / --templates
// is rejected: the runner already feeds templates via req.Options to keep
// the template directory pinned.
func TestPolicy_DropsTemplatesFlag(t *testing.T) {
	p, _ := registry.LookupArgsPolicy(toolName)
	out, dropped, err := policy.ApplyArgs([]string{"-t", "/tmp/malicious", "-severity", "high"}, p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dropped) != 1 || dropped[0].Flag != "-t" {
		t.Fatalf("expected -t dropped, got %+v", dropped)
	}
	// -severity must remain.
	if len(out) != 2 || out[0] != "-severity" || out[1] != "high" {
		t.Fatalf("expected [-severity high], got %v", out)
	}
}

// TestPolicy_DropsOutputFlag asserts -output is rejected.
func TestPolicy_DropsOutputFlag(t *testing.T) {
	p, _ := registry.LookupArgsPolicy(toolName)
	_, dropped, err := policy.ApplyArgs([]string{"-output", "/etc/passwd"}, p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dropped) != 1 || dropped[0].Flag != "-output" {
		t.Fatalf("expected -output dropped, got %+v", dropped)
	}
}
