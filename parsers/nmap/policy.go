// Per-tool args allowlist for nmap. See internal/policy for the threat model.
//
// Coverage rationale:
//   - Scan-type flags (-sS/-sT/-sV/-sU/-sn/-sC/-O) are documented and safe.
//   - Timing flags (-T0..-T5) constrain throughput, not behaviour.
//   - --top-ports and -p are scoped via target/ports validation.
//   - Output flags (-oN/-oX/-oG/-oA) are DENIED — the runner already pins
//     -oX - in nmap.go's buildArgs so XML reaches stdout. Allowing a
//     caller-supplied output path opens an arbitrary-file-write hole.
package nmap

import (
	"github.com/zero-day-ai/gibson-tool-runner/internal/policy"
	"github.com/zero-day-ai/gibson-tool-runner/internal/registry"
)

// argsPolicy enumerates safe nmap CLI flags. Add new entries only after
// confirming the flag's documented effect cannot escape the runner sandbox
// (no file writes outside the tempdir, no arbitrary code execution via
// --script that the runner has not explicitly opted into).
var argsPolicy = policy.ArgsPolicy{
	// Scan-type selectors (boolean form; no value).
	"-sS": nil, // SYN scan
	"-sT": nil, // TCP connect scan
	"-sU": nil, // UDP scan
	"-sn": nil, // ping scan (no port scan)
	"-sV": nil, // service-version detection
	"-sC": nil, // default scripts
	"-O":  nil, // OS detection
	"-A":  nil, // aggressive (-O + -sV + -sC + traceroute)
	"-Pn": nil, // skip host discovery
	"-n":  nil, // no DNS resolution
	"-v":  nil, // verbose
	"-vv": nil, // extra verbose

	// Timing templates.
	"-T0": nil,
	"-T1": nil,
	"-T2": nil,
	"-T3": nil,
	"-T4": nil,
	"-T5": nil,

	// Port spec (validated as non-empty string — caller's responsibility
	// to pass a sensible spec; format is policed by nmap itself).
	"-p":          policy.AllowAny,
	"--top-ports": policy.AllowAny,

	// Misc safe flags.
	"--reason":        nil,
	"--open":          nil,
	"--max-retries":   policy.AllowAny,
	"--host-timeout":  policy.AllowAny,
	"--max-rate":      policy.AllowAny,
	"--min-rate":      policy.AllowAny,
}

func init() {
	registry.RegisterArgsPolicy(toolName, argsPolicy)
}
