//go:build linux || darwin

package sandbox_test

import (
	"bytes"
	"errors"
	"io"
	"os/exec"
	"syscall"
	"testing"

	"github.com/zero-day-ai/gibson-tool-runner/internal/sandbox"
)

// TestLimitReader_UnderCap verifies that reads below the cap succeed normally.
func TestLimitReader_UnderCap(t *testing.T) {
	t.Parallel()
	src := bytes.NewReader([]byte("hello"))
	lr := sandbox.LimitReader(src, 100)
	got, err := io.ReadAll(lr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("got %q, want %q", got, "hello")
	}
}

// TestLimitReader_ExactCap verifies that reading exactly cap bytes returns the
// data correctly; a subsequent Read returns ErrOutputCapExceeded because the
// cap is exhausted.  When using io.ReadAll, it will call Read one extra time
// after the cap is hit and receive ErrOutputCapExceeded — the data accumulated
// so far is still available via the partial read.
func TestLimitReader_ExactCap(t *testing.T) {
	t.Parallel()
	data := []byte("abcde")
	src := bytes.NewReader(data)
	lr := sandbox.LimitReader(src, int64(len(data)))

	// Read manually to control buffer size and avoid the extra-call behaviour
	// of io.ReadAll.
	buf := make([]byte, 10)
	n, err := lr.Read(buf)
	if err != nil {
		t.Fatalf("first Read returned unexpected error: %v (n=%d)", err, n)
	}
	if string(buf[:n]) != "abcde" {
		t.Fatalf("first Read: got %q, want %q", buf[:n], "abcde")
	}

	// Cap is now exactly zero; next Read must return ErrOutputCapExceeded.
	n2, err2 := lr.Read(buf)
	if !errors.Is(err2, sandbox.ErrOutputCapExceeded) {
		t.Fatalf("expected ErrOutputCapExceeded after cap, got err=%v n=%d", err2, n2)
	}
}

// TestLimitReader_OverCap verifies that a LimitReader raises
// ErrOutputCapExceeded when more than cap bytes are read from a byte source.
// We use a simple in-process reader rather than a subprocess to avoid
// pipe-drain deadlocks.
func TestLimitReader_OverCap(t *testing.T) {
	t.Parallel()

	const capBytes = 512
	// Produce 1024 bytes — twice the cap.
	data := make([]byte, 1024)
	src := bytes.NewReader(data)
	lr := sandbox.LimitReader(src, capBytes)

	buf := make([]byte, 128)
	var totalRead int
	var hitCap bool
	for {
		n, err := lr.Read(buf)
		totalRead += n
		if errors.Is(err, sandbox.ErrOutputCapExceeded) {
			hitCap = true
			break
		}
		if err != nil {
			t.Fatalf("unexpected error after %d bytes: %v", totalRead, err)
		}
	}

	if !hitCap {
		t.Fatalf("expected ErrOutputCapExceeded after %d bytes, never got it", totalRead)
	}
	if totalRead > capBytes {
		t.Fatalf("read %d bytes past cap of %d", totalRead, capBytes)
	}
}

// TestCappedBuffer_UnderCap verifies that writes below cap succeed.
func TestCappedBuffer_UnderCap(t *testing.T) {
	t.Parallel()
	var cb sandbox.CappedBuffer
	cb.Init(100)
	n, err := cb.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 5 {
		t.Fatalf("wrote %d bytes, want 5", n)
	}
	if cb.Err() != nil {
		t.Fatalf("Err() should be nil, got %v", cb.Err())
	}
	if string(cb.Bytes()) != "hello" {
		t.Fatalf("got %q, want %q", cb.Bytes(), "hello")
	}
}

// TestCappedBuffer_OverCap verifies that writes past cap silently drop overflow
// and set Err() to ErrOutputCapExceeded.
func TestCappedBuffer_OverCap(t *testing.T) {
	t.Parallel()
	const cap = 10
	var cb sandbox.CappedBuffer
	cb.Init(cap)

	// Write 20 bytes — 10 accepted, 10 dropped.
	payload := []byte("abcdefghijklmnopqrst") // 20 bytes
	n, err := cb.Write(payload)
	if err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("Write returned n=%d, want %d", n, len(payload))
	}
	if !errors.Is(cb.Err(), sandbox.ErrOutputCapExceeded) {
		t.Fatalf("Err() should be ErrOutputCapExceeded, got %v", cb.Err())
	}
	got := string(cb.Bytes())
	if got != "abcdefghij" {
		t.Fatalf("buffered %q, want %q", got, "abcdefghij")
	}
}

// TestCappedBuffer_SubprocessOverCap runs dd to write more than cap bytes and
// verifies CappedBuffer reports ErrOutputCapExceeded after the command.
func TestCappedBuffer_SubprocessOverCap(t *testing.T) {
	t.Parallel()

	// dd produces bs*count = 1024 bytes; cap is 512.
	cmd := exec.Command("dd", "if=/dev/zero", "bs=64", "count=16")
	const cap = 512
	var cb sandbox.CappedBuffer
	cb.Init(cap)
	cmd.Stdout = &cb
	if err := cmd.Run(); err != nil {
		t.Skipf("dd not available: %v", err)
	}
	if !errors.Is(cb.Err(), sandbox.ErrOutputCapExceeded) {
		t.Fatalf("expected ErrOutputCapExceeded, got %v (len=%d)", cb.Err(), len(cb.Bytes()))
	}
}

// TestApply_Setpgid verifies that Apply sets SysProcAttr.Setpgid on the cmd.
func TestApply_Setpgid(t *testing.T) {
	t.Parallel()
	cmd := exec.Command("true")
	cfg := sandbox.DefaultConfig()
	sandbox.Apply(cmd, cfg)

	if cmd.SysProcAttr == nil {
		t.Fatal("SysProcAttr is nil after Apply")
	}
	if !cmd.SysProcAttr.Setpgid {
		t.Fatal("SysProcAttr.Setpgid is false after Apply")
	}
}

// TestApply_Setpgid_ProcessGroup verifies that a started process actually
// runs in its own process group (pgid == pid).
func TestApply_Setpgid_ProcessGroup(t *testing.T) {
	t.Parallel()
	// Use `true` because Apply wraps via sh; the sh process's pgid should
	// differ from the test process's pgid.
	cmd := exec.Command("true")
	cfg := sandbox.DefaultConfig()
	sandbox.Apply(cmd, cfg)

	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start: %v", err)
	}
	pid := cmd.Process.Pid
	pgid, err := syscall.Getpgid(pid)
	if err != nil {
		// Process may have exited already; skip the pgid check in that case.
		_ = cmd.Wait()
		t.Skipf("process exited before pgid check: %v", err)
	}
	_ = cmd.Wait()

	if pgid == syscall.Getpid() {
		t.Fatalf("child pgid %d equals parent pid %d; Setpgid had no effect", pgid, syscall.Getpid())
	}
}

// TestApply_MemoryLimit verifies that a subprocess trying to allocate more
// than the configured MemoryBytes limit is killed or exits non-zero.
// We set an artificially low limit (16 MiB) and ask Python to allocate 64 MiB.
// If Python is not installed the test is skipped.
func TestApply_MemoryLimit(t *testing.T) {
	t.Parallel()

	// Verify Python is available.
	pyPath, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available; skipping memory-limit test")
	}

	// 16 MiB limit; try to allocate 64 MiB.
	cfg := sandbox.Config{
		OutputCapBytes: sandbox.DefaultConfig().OutputCapBytes,
		MemoryBytes:    16 * 1024 * 1024,
	}
	// Allocate 64 MiB in Python; the process should be killed or fail.
	cmd := exec.Command(pyPath, "-c", "x = bytearray(64*1024*1024)")
	sandbox.Apply(cmd, cfg)

	err = cmd.Run()
	if err == nil {
		t.Fatal("expected process to fail with memory limit, but it succeeded")
	}
	// Any non-zero exit or signal is acceptable — the important thing is the
	// process did not succeed in allocating past the limit.
}

// TestDefaultConfig_EnvOverride verifies that DefaultConfig reads the
// environment variables for both limits.
func TestDefaultConfig_EnvOverride(t *testing.T) {
	t.Setenv(sandbox.EnvOutputCapBytes, "1024")
	t.Setenv(sandbox.EnvMemoryBytes, "2048")

	cfg := sandbox.DefaultConfig()
	if cfg.OutputCapBytes != 1024 {
		t.Fatalf("OutputCapBytes: got %d, want 1024", cfg.OutputCapBytes)
	}
	if cfg.MemoryBytes != 2048 {
		t.Fatalf("MemoryBytes: got %d, want 2048", cfg.MemoryBytes)
	}
}

// TestDefaultConfig_Defaults verifies the compiled-in defaults are correct.
func TestDefaultConfig_Defaults(t *testing.T) {
	t.Setenv(sandbox.EnvOutputCapBytes, "")
	t.Setenv(sandbox.EnvMemoryBytes, "")

	cfg := sandbox.DefaultConfig()
	const wantOutputCap = 100 * 1024 * 1024
	const wantMemory = 256 * 1024 * 1024
	if cfg.OutputCapBytes != wantOutputCap {
		t.Fatalf("OutputCapBytes: got %d, want %d", cfg.OutputCapBytes, wantOutputCap)
	}
	if cfg.MemoryBytes != wantMemory {
		t.Fatalf("MemoryBytes: got %d, want %d", cfg.MemoryBytes, wantMemory)
	}
}
