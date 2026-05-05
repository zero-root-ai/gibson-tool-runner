// Package policy implements the per-tool args allowlist enforced by every
// parser before appending caller-supplied req.Args to the underlying CLI's
// argv. The threat model is multi-tenant: req.Args is potentially hostile
// because it crosses a trust boundary from the daemon's mission planner
// down to a long-running tool process running with elevated capabilities
// (raw sockets for nmap/masscan/naabu, network egress for httpx/nuclei).
//
// Without a policy, an attacker who controls the mission spec can pass
// flags like `-oN /etc/passwd` (nmap), `--templates /tmp/malicious/`
// (nuclei), or `-output /var/lib/secrets/...` to coerce the tool into
// writing to or reading from an arbitrary path inside the runner pod.
//
// The policy contract:
//
//   - Every tool registers an ArgsPolicy (a map of allowed flag names to
//     a per-flag value validator). A nil ArgsPolicy means "no flags
//     allowed" — the strictest default. Output-file flags (`-oN`, `-oX`,
//     `-output`, etc.) MUST be denied unless the validator constrains
//     the value to a tool-runner-managed tempdir.
//
//   - At dispatch, the parser calls policy.ApplyArgs(req.Args, registered)
//     which returns the filtered argv plus a slice of dropped flags. The
//     parser logs each dropped flag at the structured event "tool.flag.denied"
//     (with the offending flag and reason) and either continues with the
//     allowlisted subset (default) or fails with InvalidArgument when a
//     value-validator fails — that is a "deliberate misuse" signal worth
//     a hard error rather than a silent drop.
//
//   - Adding a new tool means adding a per-tool policy file (the parser
//     package's policy.go) that lists the safe flags from the tool's
//     official documentation and any per-flag validators. Wildcards are
//     forbidden — every allowed flag must be enumerated by name.
package policy

import (
	"fmt"
	"strings"
)

// Validator is a per-flag value validator. Return nil to accept the
// supplied value, or an error to reject it (the parser will surface this
// as InvalidArgument). A nil Validator means "any non-empty value is
// acceptable" — used for boolean-style flags whose value is implicit.
type Validator func(value string) error

// ArgsPolicy maps an allowed flag name (with the leading dash, e.g. "-sV"
// or "--templates") to its value validator. Flag presence alone is not a
// signal of intent — the validator decides whether the value is OK. A
// nil map means "deny every flag" (the safest default for tools whose
// allowlist hasn't been authored yet).
type ArgsPolicy map[string]Validator

// DroppedFlag captures one rejection event so the parser can log it.
type DroppedFlag struct {
	// Flag is the offending flag name as it appeared in req.Args.
	Flag string
	// Value is the value the caller paired with the flag. Empty when
	// the flag arrived without a paired value (boolean form).
	Value string
	// Reason explains why the flag was dropped. Always non-empty.
	Reason string
}

// ApplyArgs filters req.Args against the policy.  It walks the args
// pairwise: if the current token is a flag (begins with "-") it consults
// the policy; if the next token is the flag's value (does not itself
// begin with "-") that pair is consumed.  Unrecognised flags are dropped
// and reported via the returned []DroppedFlag.  A flag whose validator
// rejects its value is reported as a hard error: callers should surface
// this as gRPC InvalidArgument rather than silently swallow it.
//
// The first return value is the filtered args (what to actually pass to
// the underlying CLI). The second is the list of dropped flags for
// structured logging. The third is a non-nil error iff a validator
// rejected a value.
func ApplyArgs(args []string, p ArgsPolicy) ([]string, []DroppedFlag, error) {
	out := make([]string, 0, len(args))
	var dropped []DroppedFlag

	for i := 0; i < len(args); i++ {
		tok := args[i]
		if !strings.HasPrefix(tok, "-") {
			// Positional value with no preceding flag — treat as a
			// stray arg and drop it. Tools whose contract demands
			// positional args feed the target via req.Target, not
			// req.Args.
			dropped = append(dropped, DroppedFlag{
				Flag:   tok,
				Reason: "stray positional token; use req.Target for the scan subject",
			})
			continue
		}

		// Detect the paired value (if any). If the next token starts
		// with "-" we treat it as a separate flag.
		var value string
		hasValue := false
		if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			value = args[i+1]
			hasValue = true
		}

		// Disallow unknown flags before consulting the validator —
		// nil-policy short-circuits here so unauthored tools deny by default.
		validator, allowed := lookup(p, tok)
		if !allowed {
			dropped = append(dropped, DroppedFlag{
				Flag:   tok,
				Value:  value,
				Reason: "flag not in tool allowlist",
			})
			if hasValue {
				i++ // consume the paired value too
			}
			continue
		}

		// Run the validator if present.
		if validator != nil {
			if !hasValue {
				return nil, dropped, fmt.Errorf(
					"flag %q requires a value but none was provided", tok)
			}
			if err := validator(value); err != nil {
				return nil, dropped, fmt.Errorf(
					"flag %q value rejected: %w", tok, err)
			}
		}

		// Allow the flag (and its value when present).
		out = append(out, tok)
		if hasValue {
			out = append(out, value)
			i++
		}
	}

	return out, dropped, nil
}

// lookup returns the validator for a flag in the policy, plus an "allowed"
// boolean. A nil policy denies every flag.
func lookup(p ArgsPolicy, flag string) (Validator, bool) {
	if p == nil {
		return nil, false
	}
	v, ok := p[flag]
	return v, ok
}

// AllowAny is a Validator that accepts any non-empty value. Use sparingly:
// most flags should have a stricter validator constraining the value's
// shape (a port range, a hostname, a path under a tempdir).
func AllowAny(value string) error {
	if value == "" {
		return fmt.Errorf("value must be non-empty")
	}
	return nil
}

// AllowEnum returns a Validator that accepts only the listed exact-match
// values. Use for flags whose values are drawn from a fixed set
// (e.g. nmap's `-T0..-T5` levels or nuclei's `-severity` enums).
func AllowEnum(allowed ...string) Validator {
	set := make(map[string]struct{}, len(allowed))
	for _, v := range allowed {
		set[v] = struct{}{}
	}
	return func(value string) error {
		if _, ok := set[value]; !ok {
			return fmt.Errorf("value %q not in allowed set", value)
		}
		return nil
	}
}

// PathUnder returns a Validator that requires the value to be a clean
// path below the supplied prefix. The prefix is typically the
// tool-runner's per-invocation tempdir, set by the runner harness in
// req.Options. Use for output-file flags (`-oN`, `-oX`, `-output`,
// `--templates`) so callers can never coerce a write or read outside
// the tempdir.
func PathUnder(prefix string) Validator {
	return func(value string) error {
		if value == "" {
			return fmt.Errorf("path must be non-empty")
		}
		// Reject path-traversal attempts and absolute paths that aren't
		// under the prefix.
		if strings.Contains(value, "..") {
			return fmt.Errorf("path %q contains '..' traversal", value)
		}
		if !strings.HasPrefix(value, prefix) {
			return fmt.Errorf("path %q is not under tempdir %q", value, prefix)
		}
		return nil
	}
}
