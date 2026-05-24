// Package sandbox applies OS-level resource limits to child processes
// launched by the tool runner.  It provides three independent controls:
//
//  1. Process-group isolation (Setpgid): the child runs in its own process
//     group so that a SIGTERM or SIGKILL targeted at -pgid reaches every
//     forked grandchild the tool may have spawned.
//
//  2. Virtual-memory ceiling (RLIMIT_AS): a hard per-child OS memory limit
//     that the kernel enforces regardless of what the child process does.
//     The limit is applied by wrapping the tool in a minimal sh(1) invocation
//     that calls `ulimit -v` before exec-ing the real binary.  This is the
//     only stdlib-compatible approach; the syscall.SysProcAttr type on
//     Linux does not expose an Rlimit slice field.
//
//  3. Output cap (LimitReader): stdout and stderr are wrapped in a
//     limitedReader that returns ErrOutputCapExceeded when more than
//     OutputCapBytes have been read.  The caller is responsible for wrapping
//     the cmd's pipe readers after calling Apply.
//
// All three limits have environment-variable overrides so operators can tune
// them via Helm values without rebuilding the image:
//
//	TOOL_RUNNER_OUTPUT_CAP_BYTES   default 100 MiB
//	TOOL_RUNNER_MEMORY_BYTES       default 256 MiB
package sandbox

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

const (
	// EnvOutputCapBytes is the env-var name for the output-cap override.
	EnvOutputCapBytes = "TOOL_RUNNER_OUTPUT_CAP_BYTES"
	// EnvMemoryBytes is the env-var name for the memory-limit override.
	EnvMemoryBytes = "TOOL_RUNNER_MEMORY_BYTES"

	defaultOutputCapBytes = 100 * 1024 * 1024 // 100 MiB
	defaultMemoryBytes    = 256 * 1024 * 1024 // 256 MiB
)

// ErrOutputCapExceeded is returned by a LimitReader when the byte cap is hit.
var ErrOutputCapExceeded = errors.New("sandbox: output cap exceeded")

// Config holds the resource limits applied to each child process.
type Config struct {
	// OutputCapBytes is the maximum number of bytes that may be read from a
	// single stdout or stderr stream.  When the limit is hit, the next Read
	// returns ErrOutputCapExceeded.  Default: 100 MiB.
	OutputCapBytes int64

	// MemoryBytes is the RLIMIT_AS hard limit (virtual address space) applied
	// to each child, expressed in bytes.  The limit is enforced by the kernel
	// via `ulimit -v` in the wrapper shell.  Default: 256 MiB.
	MemoryBytes uint64
}

// DefaultConfig returns a Config populated from environment variables if
// present, falling back to the compiled-in defaults.
func DefaultConfig() Config {
	cfg := Config{
		OutputCapBytes: defaultOutputCapBytes,
		MemoryBytes:    defaultMemoryBytes,
	}
	if v := os.Getenv(EnvOutputCapBytes); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			cfg.OutputCapBytes = n
		}
	}
	if v := os.Getenv(EnvMemoryBytes); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil && n > 0 {
			cfg.MemoryBytes = n
		}
	}
	return cfg
}

// Apply configures cmd with process-group isolation (Setpgid) and an
// RLIMIT_AS virtual-memory ceiling.
//
// The memory ceiling is implemented by wrapping the original command in a
// minimal sh(1) invocation:
//
//	sh -c "ulimit -v <kibibytes>; exec <original-binary> <args...>"
//
// This is done by replacing cmd.Path with the system shell and prepending
// the ulimit wrapper to cmd.Args.  Apply must be called before cmd.Start()
// or cmd.Run().
//
// After Apply, wrap the cmd's stdout/stderr pipes with LimitReader to enforce
// the output cap.
func Apply(cmd *exec.Cmd, cfg Config) {
	// 1. Process-group isolation: the child (and all its descendants) run in
	//    their own process group.  When the context deadline fires, exec.Cmd
	//    sends SIGKILL to -pgid, reaching grandchildren too.
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true

	// 2. RLIMIT_AS via ulimit wrapper.
	//    ulimit -v expects kibibytes; convert from bytes (round up by 1 KiB
	//    so a non-KiB-aligned limit isn't truncated).
	limitKiB := (cfg.MemoryBytes + 1023) / 1024
	applyMemoryLimit(cmd, limitKiB)
}

// LimitReader wraps r so that at most limit bytes may be read in total.
// When the cap is exceeded the next Read returns (0, ErrOutputCapExceeded).
// Partial reads that exhaust the remaining quota return the bytes up to the
// cap and then ErrOutputCapExceeded on the following call.
func LimitReader(r io.Reader, limit int64) io.Reader {
	return &limitedReader{r: r, n: limit}
}

type limitedReader struct {
	r io.Reader
	n int64
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, ErrOutputCapExceeded
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	return n, err
}

// shellWrapArgs rewrites cmd so it runs:
//
//	sh -c "ulimit -v <limitKiB>; exec <original> <args...>"
//
// The original Path and Args are replaced; Stdin/Stdout/Stderr remain
// untouched so callers can still attach pipes after calling Apply.
func shellWrapArgs(cmd *exec.Cmd, limitKiB uint64) {
	// Build a shell-quoted argument string from the original command.
	// We use printf %q-style single-quoting via shellQuote to handle spaces
	// and special characters in arguments safely.
	inner := shellQuoteSlice(cmd.Args)
	script := fmt.Sprintf("ulimit -v %d; exec %s", limitKiB, inner)

	shPath := "/bin/sh"
	if p, err := exec.LookPath("sh"); err == nil {
		shPath = p
	}
	cmd.Path = shPath
	cmd.Args = []string{"sh", "-c", script}
}

// shellQuoteSlice produces a single shell word for each element in args and
// joins them with spaces.  Each word is wrapped in single-quotes; any
// single-quote inside the word is escaped as '\''.
func shellQuoteSlice(args []string) string {
	if len(args) == 0 {
		return ""
	}
	out := make([]byte, 0, 128)
	for i, a := range args {
		if i > 0 {
			out = append(out, ' ')
		}
		out = append(out, '\'')
		for j := 0; j < len(a); j++ {
			if a[j] == '\'' {
				out = append(out, '\'', '\\', '\'', '\'')
			} else {
				out = append(out, a[j])
			}
		}
		out = append(out, '\'')
	}
	return string(out)
}

// CappedBuffer is a drop-in replacement for bytes.Buffer that is safe to use
// as cmd.Stdout / cmd.Stderr.  It accepts writes up to Cap bytes; the first
// write that would exceed the cap is truncated and the overflow is silently
// discarded.  After the command finishes, callers should call Err() to check
// whether the cap was hit.
//
//	var stdout sandbox.CappedBuffer
//	stdout.Init(cfg.OutputCapBytes)
//	cmd.Stdout = &stdout
//	cmd.Run()
//	if err := stdout.Err(); errors.Is(err, sandbox.ErrOutputCapExceeded) { ... }
type CappedBuffer struct {
	buf bytes.Buffer
	cap int64
	rem int64
	hit bool
}

// Init sets the byte cap.  Must be called before the first write.
func (c *CappedBuffer) Init(cap int64) {
	c.cap = cap
	c.rem = cap
}

// Write implements io.Writer.  Bytes beyond the cap are silently dropped and
// the overflow flag is set.
func (c *CappedBuffer) Write(p []byte) (int, error) {
	if c.rem <= 0 {
		c.hit = true
		// Report success so the subprocess's write does not fail (we want the
		// process to keep running; we just stop buffering).
		return len(p), nil
	}
	accept := int64(len(p))
	if accept > c.rem {
		accept = c.rem
		c.hit = true
	}
	n, err := c.buf.Write(p[:accept])
	c.rem -= int64(n)
	// Always report the full len(p) consumed so the caller (cmd's internal
	// I/O copier) does not think the write failed.
	return len(p), err
}

// Bytes returns the buffered bytes (up to Cap).
func (c *CappedBuffer) Bytes() []byte { return c.buf.Bytes() }

// Err returns ErrOutputCapExceeded if the cap was hit, otherwise nil.
func (c *CappedBuffer) Err() error {
	if c.hit {
		return ErrOutputCapExceeded
	}
	return nil
}
