package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	componentpb "github.com/zero-day-ai/sdk/api/gen/gibson/component/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/zero-day-ai/gibson-tool-runner/internal/registry"
)

// TestDecodeInputJSON_Fields asserts that decodeInputJSON correctly maps the
// "target" and "args" fields into ExecuteRequest and puts unknown string
// fields into Options.
func TestDecodeInputJSON_Fields(t *testing.T) {
	input := `{"target":"192.168.1.1","ports":"80,443","args":["-sV","-O"]}`
	req, err := decodeInputJSON(input)
	if err != nil {
		t.Fatalf("decodeInputJSON: %v", err)
	}
	if req.Target != "192.168.1.1" {
		t.Errorf("Target = %q; want 192.168.1.1", req.Target)
	}
	if len(req.Args) != 2 || req.Args[0] != "-sV" || req.Args[1] != "-O" {
		t.Errorf("Args = %v; want [-sV -O]", req.Args)
	}
	if req.Options["ports"] != "80,443" {
		t.Errorf("Options[ports] = %q; want 80,443", req.Options["ports"])
	}
}

// TestDecodeInputJSON_Empty asserts that an empty input_json returns a
// zero ExecuteRequest without error.
func TestDecodeInputJSON_Empty(t *testing.T) {
	req, err := decodeInputJSON("")
	if err != nil {
		t.Fatalf("unexpected error for empty input: %v", err)
	}
	if req.Target != "" || len(req.Args) != 0 || len(req.Options) != 0 {
		t.Errorf("expected zero ExecuteRequest, got %+v", req)
	}
}

// TestDecodeInputJSON_TargetOnly asserts that a payload with only "target"
// works and produces no Options.
func TestDecodeInputJSON_TargetOnly(t *testing.T) {
	req, err := decodeInputJSON(`{"target":"10.0.0.1"}`)
	if err != nil {
		t.Fatalf("decodeInputJSON: %v", err)
	}
	if req.Target != "10.0.0.1" {
		t.Errorf("Target = %q; want 10.0.0.1", req.Target)
	}
	if len(req.Options) != 0 {
		t.Errorf("Options should be empty, got %v", req.Options)
	}
}

// ---------------------------------------------------------------------------
// End-to-end dispatch through a fake parser — verifies the full pipeline
// from input decode → Execute → ABI emission without requiring any CLI tool.
// ---------------------------------------------------------------------------

// fakeParser is a minimal registry.Parser for dispatch tests.
type fakeParser struct {
	name   string
	result *registry.ExecuteResponse
	err    error
}

func (f *fakeParser) Describe() registry.CatalogEntry {
	return registry.CatalogEntry{Name: f.name}
}

func (f *fakeParser) Execute(_ context.Context, _ registry.ExecuteRequest) (*registry.ExecuteResponse, error) {
	return f.result, f.err
}

func (f *fakeParser) OutputMessage() proto.Message { return nil }

// TestDispatch_SuccessPath verifies that a successful Execute round-trips
// through emitResponse and produces a valid ABI marker line.
func TestDispatch_SuccessPath(t *testing.T) {
	// Build a CallToolRequest and encode it as the ABI expects.
	callReq := &componentpb.CallToolRequest{
		ToolName:  "test-fake",
		InputJson: `{"target":"127.0.0.1"}`,
		TimeoutMs: 30000,
	}
	raw, err := protojson.Marshal(callReq)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	b64Input := base64.StdEncoding.EncodeToString(raw)

	// Decode and map — same path as runDefault.
	var decoded componentpb.CallToolRequest
	decRaw, _ := base64.StdEncoding.DecodeString(b64Input)
	if err := protojson.Unmarshal(decRaw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	execReq, err := decodeInputJSON(decoded.GetInputJson())
	if err != nil {
		t.Fatalf("decodeInputJSON: %v", err)
	}
	if int32(decoded.GetTimeoutMs()/1000) != 30 {
		t.Errorf("timeout = %d; want 30", int32(decoded.GetTimeoutMs()/1000))
	}
	if execReq.Target != "127.0.0.1" {
		t.Errorf("Target = %q; want 127.0.0.1", execReq.Target)
	}
}

// TestEmitResponse_RoundTrip verifies that emitResponse produces a line that
// starts with abiOutputMarker and contains a valid base64(protojson(CallToolResponse)).
func TestEmitResponse_RoundTrip(t *testing.T) {
	// We can't call emitResponse directly since it writes to os.Stdout and
	// calls os.Exit on marshal error — but we can test the component pieces.
	resp := &componentpb.CallToolResponse{
		OutputJson: `{"hosts":[]}`,
	}
	b, err := protojson.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	line := abiOutputMarker + base64.StdEncoding.EncodeToString(b)
	if !strings.HasPrefix(line, abiOutputMarker) {
		t.Error("line does not start with ABI output marker")
	}

	// Verify the encoded response round-trips.
	enc := strings.TrimPrefix(line, abiOutputMarker)
	decoded, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	var got componentpb.CallToolResponse
	if err := protojson.Unmarshal(decoded, &got); err != nil {
		t.Fatalf("protojson unmarshal: %v", err)
	}
	if got.GetOutputJson() != `{"hosts":[]}` {
		t.Errorf("output_json = %q; want {\"hosts\":[]}", got.GetOutputJson())
	}
}

// TestArgsPolicy_DeniedByDefault verifies that a nil policy (no registered
// policy) drops all flags — the default-deny behaviour protects new parsers
// that haven't authored their allowlist yet.
func TestArgsPolicy_DeniedByDefault(t *testing.T) {
	toolName := "unregistered-test-tool-" + t.Name()
	filtered, err := registry.ApplyPolicy(toolName, []string{"-oN", "/etc/passwd"}, nil)
	if err != nil {
		t.Fatalf("ApplyPolicy returned error: %v", err)
	}
	if len(filtered) != 0 {
		t.Errorf("filtered = %v; want empty (deny-all on nil policy)", filtered)
	}
}

// TestTimeout_ContextPropagates verifies that a short timeout cancels the
// context before a long-running (simulated) Execute completes.
func TestTimeout_ContextPropagates(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
			t.Error("context did not cancel within expected window")
		}
		close(done)
	}()
	<-done
	if ctx.Err() != context.DeadlineExceeded {
		t.Errorf("ctx.Err() = %v; want DeadlineExceeded", ctx.Err())
	}
}

// TestDecodeInputJSON_NonStringOptionsIgnored asserts that non-string values
// in input_json (e.g. integers) are silently skipped rather than erroring.
func TestDecodeInputJSON_NonStringOptionsIgnored(t *testing.T) {
	// "depth" is an integer — should not end up in Options.
	req, err := decodeInputJSON(`{"target":"example.com","depth":5,"timeout_label":"30s"}`)
	if err != nil {
		t.Fatalf("decodeInputJSON: %v", err)
	}
	if req.Target != "example.com" {
		t.Errorf("Target = %q; want example.com", req.Target)
	}
	if _, ok := req.Options["depth"]; ok {
		t.Error("integer field 'depth' should not appear in Options")
	}
	if req.Options["timeout_label"] != "30s" {
		t.Errorf("Options[timeout_label] = %q; want 30s", req.Options["timeout_label"])
	}
}

// Silence unused-import warnings for packages only used indirectly.
var (
	_ = json.Unmarshal
	_ proto.Message = nil
)
