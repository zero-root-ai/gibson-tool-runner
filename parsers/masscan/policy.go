// Per-tool args allowlist for masscan.
//
// Coverage rationale:
//   - Output flags (`-oN`, `-oX`, `-oJ`, `-oG`, `--output-filename`) DENIED.
//     The runner pins `-oJ -` so JSON reaches stdout; allowing caller-
//     supplied output paths is the canonical example of arbitrary file
//     write via tool injection.
//   - Throughput / scope flags safe.
package masscan

import (
	"github.com/zero-day-ai/gibson-tool-runner/internal/policy"
	"github.com/zero-day-ai/gibson-tool-runner/internal/registry"
)

var argsPolicy = policy.ArgsPolicy{
	"-p":          policy.AllowAny,
	"--ports":     policy.AllowAny,
	"--rate":      policy.AllowAny,
	"--top-ports": policy.AllowAny,
	"--exclude":   policy.AllowAny,
	"--banners":   nil,
	"--ping":      nil,
	"-v":          nil,
	"-vv":         nil,
	"--retries":   policy.AllowAny,
}

func init() {
	registry.RegisterArgsPolicy(toolName, argsPolicy)
}
