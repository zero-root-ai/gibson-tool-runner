// Per-tool args allowlist for amass.
//
// Coverage rationale:
//   - Subcommand "enum" plus -passive / -json /dev/stdout already pinned.
//   - Output-redirect flags (`-o`, `-dir`) DENIED — runner reads JSON on
//     stdout. The amass `-config` flag is DENIED to prevent loading
//     attacker-controlled configurations.
package amass

import (
	"github.com/zero-day-ai/gibson-tool-runner/internal/policy"
	"github.com/zero-day-ai/gibson-tool-runner/internal/registry"
)

var argsPolicy = policy.ArgsPolicy{
	"-passive":  nil,
	"-active":   nil,
	"-brute":    nil,
	"-w":        policy.AllowAny, // wordlist (still requires path validator
	                              // to be added before use; keep narrow)
	"-timeout":  policy.AllowAny,
	"-max-depth": policy.AllowAny,
	"-min-for-recursive": policy.AllowAny,
	"-include":  policy.AllowAny,
	"-exclude":  policy.AllowAny,
	"-silent":   nil,
	"-nolocaldb": nil,
}

func init() {
	registry.RegisterArgsPolicy(toolName, argsPolicy)
}
