package amass

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zero-day-ai/gibson-tool-runner/internal/registry"
)

func TestParseJSONLines(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "simple.jsonl"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	disc, quality, err := parseJSONLines(raw, "example.com")
	if err != nil {
		t.Fatalf("parseJSONLines: %v", err)
	}
	if quality != registry.ParseQualityStructured {
		t.Errorf("quality = %d; want STRUCTURED", quality)
	}
	if got := len(disc.Domains); got != 1 {
		t.Fatalf("domains = %d; want 1", got)
	}
	if got := len(disc.Subdomains); got != 3 {
		t.Fatalf("subdomains = %d; want 3", got)
	}
	// 2 distinct IPs → 2 hosts (dedup works).
	if got := len(disc.Hosts); got != 2 {
		t.Fatalf("hosts = %d; want 2 (dedup by IP)", got)
	}
}

func TestRegistryIntegration(t *testing.T) {
	if _, ok := registry.Lookup(toolName); !ok {
		t.Fatalf("registry.Lookup(%q) = false", toolName)
	}
}
