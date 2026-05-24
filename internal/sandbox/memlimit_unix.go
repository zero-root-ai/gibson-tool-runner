//go:build linux || darwin

package sandbox

import "os/exec"

// applyMemoryLimit rewrites cmd to run under a shell wrapper that applies
// `ulimit -v <limitKiB>` before exec-ing the real binary.  This is the
// only portable stdlib-only mechanism for enforcing RLIMIT_AS in a child
// process: the Go syscall package's SysProcAttr does not expose an Rlimit
// slice on Linux, so we rely on the shell's built-in ulimit to set the
// limit in the child's address space before the tool binary is exec'd.
func applyMemoryLimit(cmd *exec.Cmd, limitKiB uint64) {
	shellWrapArgs(cmd, limitKiB)
}
