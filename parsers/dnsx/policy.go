// Per-tool args allowlist for dnsx.
//
// Coverage rationale:
//   - Record-type selectors are safe.
//   - Output flags (`-o`, `-output`) DENIED — runner reads JSON on stdout.
//   - Resolver-list (`-r`) DENIED unless paired with PathUnder validator;
//     allowing arbitrary resolver lists could exfiltrate via DNS to a
//     caller-controlled server. Today no caller needs to override the
//     default resolvers, so this is left out of the allowlist.
package dnsx

import (
	"github.com/zero-day-ai/gibson-tool-runner/internal/policy"
	"github.com/zero-day-ai/gibson-tool-runner/internal/registry"
)

var argsPolicy = policy.ArgsPolicy{
	// Record-type selectors (boolean form).
	"-a":     nil,
	"-aaaa":  nil,
	"-cname": nil,
	"-ns":    nil,
	"-txt":   nil,
	"-mx":    nil,
	"-soa":   nil,
	"-ptr":   nil,
	"-srv":   nil,
	"-caa":   nil,
	"-axfr":  nil,

	// Throughput / behaviour.
	"-rate-limit": policy.AllowAny,
	"-rl":         policy.AllowAny,
	"-c":          policy.AllowAny,
	"-t":          policy.AllowAny,
	"-retry":      policy.AllowAny,

	// Boolean diagnostics.
	"-silent":  nil,
	"-stats":   nil,
	"-resp":    nil,
	"-resp-only": nil,
}

func init() {
	registry.RegisterArgsPolicy(toolName, argsPolicy)
}
