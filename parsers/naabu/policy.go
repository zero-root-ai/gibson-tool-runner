// Per-tool args allowlist for naabu.
//
// Coverage rationale:
//   - Port spec / scan-mode flags safe and documented.
//   - Output flags (`-o`, `-output`, `-csv`, `-json` already pinned) are
//     DENIED. The runner consumes JSON on stdout via -json -silent.
package naabu

import (
	"github.com/zero-day-ai/gibson-tool-runner/internal/policy"
	"github.com/zero-day-ai/gibson-tool-runner/internal/registry"
)

var argsPolicy = policy.ArgsPolicy{
	// Port specification.
	"-p":          policy.AllowAny,
	"-top-ports":  policy.AllowAny,
	"-exclude-ports": policy.AllowAny,

	// Scan-mode flags.
	"-scan-type":  policy.AllowEnum("s", "c", "syn", "connect"),
	"-s":          policy.AllowEnum("s", "c", "syn", "connect"),
	"-Pn":         nil,
	"-sn":         nil,

	// Throughput.
	"-rate":       policy.AllowAny,
	"-c":          policy.AllowAny,
	"-timeout":    policy.AllowAny,
	"-retries":    policy.AllowAny,

	// Boolean diagnostics.
	"-stats":      nil,
	"-silent":     nil,
	"-verify":     nil,
}

func init() {
	registry.RegisterArgsPolicy(toolName, argsPolicy)
}
