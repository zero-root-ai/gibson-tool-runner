package policy

import (
	"strings"
	"testing"
)

func TestApplyArgs_NilPolicy_DeniesEverything(t *testing.T) {
	args := []string{"-sV", "--scripts", "vuln"}
	out, dropped, err := ApplyArgs(args, nil)
	if err != nil {
		t.Fatalf("unexpected validator error: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected zero allowed args, got %v", out)
	}
	if len(dropped) != 2 {
		t.Fatalf("expected 2 dropped flags, got %d (%v)", len(dropped), dropped)
	}
	if dropped[0].Flag != "-sV" || dropped[1].Flag != "--scripts" {
		t.Fatalf("unexpected dropped flags: %+v", dropped)
	}
}

func TestApplyArgs_AllowsListedFlag(t *testing.T) {
	policy := ArgsPolicy{"-sV": nil}
	out, dropped, err := ApplyArgs([]string{"-sV"}, policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dropped) != 0 {
		t.Fatalf("expected 0 dropped, got %v", dropped)
	}
	if len(out) != 1 || out[0] != "-sV" {
		t.Fatalf("expected [-sV], got %v", out)
	}
}

func TestApplyArgs_DropsUnknownFlag_WithValue(t *testing.T) {
	policy := ArgsPolicy{"-sV": nil}
	out, dropped, err := ApplyArgs([]string{"-oN", "/etc/passwd", "-sV"}, policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 1 || out[0] != "-sV" {
		t.Fatalf("expected only [-sV], got %v", out)
	}
	if len(dropped) != 1 {
		t.Fatalf("expected 1 dropped, got %d", len(dropped))
	}
	if dropped[0].Flag != "-oN" || dropped[0].Value != "/etc/passwd" {
		t.Fatalf("expected -oN /etc/passwd dropped, got %+v", dropped[0])
	}
	if !strings.Contains(dropped[0].Reason, "allowlist") {
		t.Fatalf("expected reason to mention allowlist, got %q", dropped[0].Reason)
	}
}

func TestApplyArgs_ValidatorErrorReturnsError(t *testing.T) {
	policy := ArgsPolicy{
		"--severity": AllowEnum("low", "medium", "high"),
	}
	_, _, err := ApplyArgs([]string{"--severity", "critical"}, policy)
	if err == nil {
		t.Fatal("expected validator error, got nil")
	}
	if !strings.Contains(err.Error(), "--severity") {
		t.Fatalf("expected error to mention --severity, got %v", err)
	}
}

func TestApplyArgs_StrayPositional_Dropped(t *testing.T) {
	policy := ArgsPolicy{"-sV": nil}
	_, dropped, err := ApplyArgs([]string{"hello", "-sV"}, policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dropped) != 1 || dropped[0].Flag != "hello" {
		t.Fatalf("expected hello dropped, got %v", dropped)
	}
}

func TestApplyArgs_PathUnder_RejectsTraversal(t *testing.T) {
	policy := ArgsPolicy{"-oN": PathUnder("/runner/tmp/")}
	_, _, err := ApplyArgs([]string{"-oN", "/runner/tmp/../etc/passwd"}, policy)
	if err == nil {
		t.Fatal("expected traversal rejection")
	}
}

func TestApplyArgs_PathUnder_RejectsOutsidePrefix(t *testing.T) {
	policy := ArgsPolicy{"-oN": PathUnder("/runner/tmp/")}
	_, _, err := ApplyArgs([]string{"-oN", "/etc/passwd"}, policy)
	if err == nil {
		t.Fatal("expected outside-prefix rejection")
	}
}

func TestApplyArgs_PathUnder_AllowsWithinPrefix(t *testing.T) {
	policy := ArgsPolicy{"-oN": PathUnder("/runner/tmp/")}
	out, dropped, err := ApplyArgs([]string{"-oN", "/runner/tmp/output.txt"}, policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dropped) != 0 {
		t.Fatalf("expected 0 dropped, got %v", dropped)
	}
	if len(out) != 2 || out[0] != "-oN" || out[1] != "/runner/tmp/output.txt" {
		t.Fatalf("expected -oN /runner/tmp/output.txt, got %v", out)
	}
}

func TestAllowEnum_Behavior(t *testing.T) {
	v := AllowEnum("alpha", "beta")
	if err := v("alpha"); err != nil {
		t.Fatalf("alpha should pass: %v", err)
	}
	if err := v("gamma"); err == nil {
		t.Fatal("gamma should fail")
	}
}

func TestAllowAny_RejectsEmpty(t *testing.T) {
	if err := AllowAny(""); err == nil {
		t.Fatal("empty should fail")
	}
	if err := AllowAny("anything"); err != nil {
		t.Fatalf("nonempty should pass: %v", err)
	}
}
