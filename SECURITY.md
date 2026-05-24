# Security model — gibson-tool-runner

This document describes the security boundaries of `gibson-tool-runner`
and the per-tool args allowlist that protects long-running CLI tools
(nmap, nuclei, masscan, …) from caller-controlled flag injection.

## Threat model

The tool runner runs inside a Kubernetes pod with elevated capabilities:

- `nmap`, `masscan`, `naabu` need raw-socket access (`CAP_NET_RAW`).
- `httpx`, `nuclei` make outbound HTTP requests to caller-specified
  targets.
- All tools can in principle write to the pod filesystem.

The `req.Args []string` field in every parser's `ExecuteRequest` arrives
from the daemon's mission planner, which builds it from the **mission
spec** the operator (or a delegated user) submitted. In a multi-tenant
deployment, the mission spec is a hostile input boundary: callers can
include any string they want in `req.Args`, and without filtering those
strings flow directly into the tool's argv. Tools then interpret those
arguments according to **their** documented behaviour — which often
includes flags that read or write arbitrary paths, such as nmap's
`-oN <file>`, masscan's `-oX <file>`, or nuclei's `-templates <dir>`.

The threat: a malicious or compromised mission spec can use a
plain-looking tool invocation to read or write any file the tool has
access to inside the runner pod, including:

- Kubernetes service account tokens at `/var/run/secrets/.../token`
- Mounted Vault secrets
- Other tenants' working files in shared scratch volumes

## Defense: per-tool args allowlist

`internal/policy/policy.go` provides the `ArgsPolicy` type — a map of
**permitted flag name → value validator**. Every parser registers its
allowlist via `registry.RegisterArgsPolicy(toolName, policy)` from the
`policy.go` file in its package.

At dispatch, the parser calls `registry.ApplyPolicy(toolName, req.Args, log)`
which:

1. Looks up the registered policy.
2. Filters `req.Args` against the allowlist:
   - Unknown flags are **dropped** with a structured log event
     `tool.flag.denied`.
   - Allowed flags whose value fails the validator return a hard error
     (the parser surfaces this as `InvalidArgument`).
   - A nil policy = "deny every flag" (the strictest default).
3. Returns the filtered argv to feed the underlying CLI.

Output-file flags (e.g. `-oN`, `-oX`, `-output`, `-templates`,
`--output-filename`) are **denied by default** for every tool. The runner
itself pins the canonical output target (e.g. `-oX -` for nmap, `-oJ -`
for masscan) and consumes the result on stdout. There is no legitimate
reason for a caller to override this, and allowing it opens an arbitrary
file write or read.

## How to add a new tool

1. Create the parser package under `parsers/<tool>/`.
2. In its `policy.go`, list every safe flag from the tool's official
   documentation (one map entry per flag), with the appropriate
   validator. Use `policy.AllowAny` only when the value's shape is
   policed by the tool itself; prefer `policy.AllowEnum(...)` for
   bounded sets and `policy.PathUnder(prefix)` for any path argument.
3. In the parser's `Execute`, replace the direct `args = append(args,
   req.Args...)` with:
   ```go
   filtered, err := registry.ApplyPolicy(toolName, req.Args, nil)
   if err != nil {
       return &registry.ExecuteResponse{ParseQuality: registry.ParseQualityFailed},
           fmt.Errorf("<tool> args policy: %w", err)
   }
   args = append(args, filtered...)
   ```
4. Add a `policy_test.go` under the same package asserting:
   - The canonical output-file injection (e.g. `-oN /etc/passwd`) is
     dropped with `tool.flag.denied`.
   - At least one documented safe flag passes through unchanged.

## How to add a new safe flag to an existing tool

Append the entry to the tool's `argsPolicy` map in `policy.go`. Verify
the existing tests still pass and add a new test asserting the new flag
is allowed under happy-path inputs.

## Output-file flag policy

Output-file flags are the most common attack surface. Each tool's
`policy.go` enumerates every output flag and **does not** include them
in the allowlist. If a future feature legitimately needs a tool to write
to a path the caller controls, the validator must be `policy.PathUnder`
constrained to a runner-managed tempdir — never a free-form path.

## Process sandbox (`internal/sandbox`)

Every tool invocation is additionally wrapped by the sandbox package,
which applies three OS-level controls that are orthogonal to the args
allowlist:

### 1. Process-group isolation (`Setpgid`)

Each child process runs in its own process group (`SysProcAttr.Setpgid
= true`).  When the per-call deadline fires, the Go runtime sends
`SIGKILL` to the entire group (`kill(-pgid, SIGKILL)`), reaching any
grandchildren the tool may have forked.  Without this, a process that
forks a grandchild and exits can leave the grandchild running
indefinitely inside the pod.

### 2. Virtual-memory ceiling (RLIMIT_AS)

Each child is wrapped in a minimal shell invocation:

```
sh -c "ulimit -v <kibibytes>; exec <tool> <args...>"
```

This sets the POSIX `RLIMIT_AS` (virtual address space) hard limit for
the tool process before it executes.  A tool that tries to allocate
more than the configured ceiling will receive `ENOMEM` and exit
non-zero.

Default: **256 MiB**.  Override per-deployment with the environment
variable `TOOL_RUNNER_MEMORY_BYTES` (bytes).

The Helm chart exposes this as:
```yaml
sandbox:
  memoryMiB: 256   # TOOL_RUNNER_MEMORY_BYTES = memoryMiB * 1024 * 1024
```

### 3. Output cap (`CappedBuffer`)

Each child's stdout and stderr are captured through a `CappedBuffer`
writer.  Bytes beyond the configured cap are silently dropped in memory
(the subprocess continues running — it can still write) and
`CappedBuffer.Err()` returns `ErrOutputCapExceeded` after the run.
The parser surfaces this as a hard error rather than silently
truncating the result.

Default: **100 MiB per stream**.  Override with
`TOOL_RUNNER_OUTPUT_CAP_BYTES` (bytes).

The Helm chart exposes this as:
```yaml
sandbox:
  outputCapMiB: 100   # TOOL_RUNNER_OUTPUT_CAP_BYTES = outputCapMiB * 1024 * 1024
```

### Helm values (enterprise/deploy)

The Helm chart for the tool runner maps `sandbox.outputCapMiB` and
`sandbox.memoryMiB` values into the container's env vars:

```yaml
# values.yaml
sandbox:
  outputCapMiB: 100
  memoryMiB: 256
```

```yaml
# templates/deployment.yaml
env:
  - name: TOOL_RUNNER_OUTPUT_CAP_BYTES
    value: "{{ mul .Values.sandbox.outputCapMiB 1048576 }}"
  - name: TOOL_RUNNER_MEMORY_BYTES
    value: "{{ mul .Values.sandbox.memoryMiB 1048576 }}"
```

## What is NOT covered by the allowlist

- The `req.Target` field still goes directly into argv as the last arg.
  Each tool's parser is expected to validate `req.Target` per its own
  documented format (IPv4/IPv6/CIDR/hostname). Cross-tool target
  validation lives outside this policy and is the daemon's
  responsibility.
- Resource limits (timeout, network rate-limit) are enforced by the
  pod's runtime constraints and the per-tool defaults in
  `CatalogEntry.DefaultTimeoutSeconds` / `Resources` — not by the args
  allowlist.

## Reporting issues

If you find a bypass — a flag that escapes a validator, a way to inject
an unknown flag through positional encoding, or any other escape — open
an issue with the reproduction steps. Do **not** open a public issue if
the bypass enables tenant-isolation breakage; email security at the
project address instead.
