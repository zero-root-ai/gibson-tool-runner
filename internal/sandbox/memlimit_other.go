//go:build !linux && !darwin

package sandbox

import "os/exec"

// applyMemoryLimit is a no-op on platforms where ulimit -v is not reliably
// available.  Process-group isolation (Setpgid) and output caps (LimitReader)
// still apply; only the RLIMIT_AS enforcement is absent.
func applyMemoryLimit(_ *exec.Cmd, _ uint64) {}
