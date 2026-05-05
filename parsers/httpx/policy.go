// Per-tool args allowlist for httpx.
//
// Coverage rationale:
//   - Detection / filter flags safe and documented.
//   - Output flags (`-o`, `-output`, `-store-response*`, `-srd`) DENIED.
//   - Probe-modification flags that allow caller-controlled arbitrary
//     payloads (`-X` custom method, `-body`) are allowed but value-bound
//     so callers cannot inject newline-separated multi-request payloads.
package httpx

import (
	"fmt"
	"strings"

	"github.com/zero-day-ai/gibson-tool-runner/internal/policy"
	"github.com/zero-day-ai/gibson-tool-runner/internal/registry"
)

// noNewlines rejects values containing '\n' / '\r' (HTTP request smuggling
// guard: httpx threads `-body` directly into the request body).
func noNewlines(value string) error {
	if strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("value must not contain newlines")
	}
	return nil
}

var argsPolicy = policy.ArgsPolicy{
	// Probe-shape flags.
	"-method":        policy.AllowEnum("GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE"),
	"-X":             policy.AllowEnum("GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE"),
	"-path":          noNewlines,
	"-paths":         noNewlines,
	"-ports":         policy.AllowAny,
	"-p":             policy.AllowAny,
	"-body":          noNewlines,
	"-H":             noNewlines,
	"-status-code":   policy.AllowAny,
	"-sc":            nil,
	"-content-length": nil,
	"-cl":            nil,
	"-content-type":  nil,
	"-ct":            nil,
	"-title":         nil,
	"-tech-detect":   nil,
	"-td":            nil,
	"-web-server":    nil,
	"-server":        nil,

	// Filtering.
	"-mc": policy.AllowAny,
	"-fc": policy.AllowAny,
	"-ms": policy.AllowAny,
	"-fs": policy.AllowAny,

	// Throughput.
	"-threads":     policy.AllowAny,
	"-t":           policy.AllowAny,
	"-rate-limit":  policy.AllowAny,
	"-rl":          policy.AllowAny,
	"-timeout":     policy.AllowAny,
	"-retries":     policy.AllowAny,

	// Boolean diagnostics.
	"-silent":       nil,
	"-no-color":     nil,
	"-stats":        nil,
	"-follow-redirects": nil,
	"-fr":           nil,
}

func init() {
	registry.RegisterArgsPolicy(toolName, argsPolicy)
}
