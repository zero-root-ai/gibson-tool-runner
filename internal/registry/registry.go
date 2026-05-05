// Package registry is the central map of parsers registered in the runner
// binary. Each parser file under parsers/ registers itself here via init(),
// so adding a parser is a single-file change: create parsers/<tool>/<tool>.go
// and call registry.Register(&myParser{}) in its init().
package registry

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"

	graphragpb "github.com/zero-day-ai/sdk/api/gen/gibson/graphrag/v1"
	"google.golang.org/protobuf/proto"

	"github.com/zero-day-ai/gibson-tool-runner/internal/policy"
)

// ExecuteRequest is the typed input every parser receives. Callers build it
// from the decoded env-in proto before dispatching to Parser.Run.
type ExecuteRequest struct {
	Target  string
	Args    []string
	Options map[string]string
	Timeout int32
}

// ExecuteResponse is the canonical runner output. Field-100-equivalent
// DiscoveryResult carries the taxonomy-aligned nodes; Stdout and Stderr
// preserve raw CLI output for diagnostics. ParseQuality tags richness so
// graph queries can filter.
type ExecuteResponse struct {
	ExitCode     int32
	Stdout       []byte
	Stderr       []byte
	ParseQuality ParseQuality
	Discovery    *graphragpb.DiscoveryResult
}

// ParseQuality mirrors gibson.component.v1.ParseQuality.
type ParseQuality int32

const (
	ParseQualityUnspecified ParseQuality = 0
	ParseQualityStructured  ParseQuality = 1
	ParseQualityPartial     ParseQuality = 2
	ParseQualityRaw         ParseQuality = 3
	ParseQualityFailed      ParseQuality = 4
)

// CatalogEntry is the self-description a parser emits via Parser.Describe;
// the runner's --list-tools command collects these and prints them as a JSON
// array that the Gibson daemon's catalog refresher ingests.
type CatalogEntry struct {
	Name                  string            `json:"name"`
	Version               string            `json:"version"`
	Description           string            `json:"description"`
	Tags                  []string           `json:"tags"`
	InputSchema           map[string]any    `json:"input_schema"`
	OutputProtoType       string            `json:"output_proto_type"`
	DefaultParseQuality   ParseQuality      `json:"default_parse_quality"`
	Resources             ResourceHint      `json:"resources"`
	DefaultTimeoutSeconds int32             `json:"default_timeout_seconds"`
}

// ResourceHint is a per-tool suggested sandbox size. Operators can override
// in daemon config; the runner's hint is authoritative for first-class fit.
type ResourceHint struct {
	VCPU   int32  `json:"vcpu"`
	Memory string `json:"memory"`
}

// Parser is the contract every tool parser implements.
type Parser interface {
	// Describe returns the catalog entry for this parser — rendered in
	// --list-tools output and consumed by the Gibson daemon's refresher.
	Describe() CatalogEntry

	// Execute runs the underlying CLI with args built from the request and
	// parses the output into a DiscoveryResult. Implementations must populate
	// response.ParseQuality even on failure.
	Execute(ctx context.Context, req ExecuteRequest) (*ExecuteResponse, error)

	// OutputMessage returns a fresh empty proto.Message matching
	// CatalogEntry.OutputProtoType. The runner uses this to decide whether
	// a response-shaped wrapping is expected (v0.2+; today all parsers return
	// the canonical ExecuteResponse so this returns nil).
	OutputMessage() proto.Message
}

var (
	mu        sync.RWMutex
	parsers   = map[string]Parser{}
	registry  []Parser
	policies  = map[string]policy.ArgsPolicy{}
)

// Register records a parser in the global table. Panics if the name is
// already taken — parsers collide only on author error, never at runtime.
func Register(p Parser) {
	mu.Lock()
	defer mu.Unlock()
	name := p.Describe().Name
	if name == "" {
		panic("registry: parser Describe().Name is empty")
	}
	if _, dup := parsers[name]; dup {
		panic(fmt.Sprintf("registry: duplicate parser %q", name))
	}
	parsers[name] = p
	registry = append(registry, p)
}

// RegisterArgsPolicy associates a per-tool args allowlist with a tool name.
// Parsers should call this from init() right after Register() so the
// allowlist is in place before any Execute() reaches ApplyPolicy.
//
// Tools with no registered policy default-deny every flag — see
// policy.ApplyArgs's nil-policy semantics. That is intentional: failing
// closed prevents an oversight in a new tool's onboarding from opening
// a flag-injection hole.
func RegisterArgsPolicy(toolName string, p policy.ArgsPolicy) {
	mu.Lock()
	defer mu.Unlock()
	if toolName == "" {
		panic("registry: RegisterArgsPolicy with empty tool name")
	}
	policies[toolName] = p
}

// LookupArgsPolicy returns the registered policy for a tool. Second
// return is false when no policy was registered (deny-all default).
func LookupArgsPolicy(toolName string) (policy.ArgsPolicy, bool) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := policies[toolName]
	return p, ok
}

// ApplyPolicy is the canonical entry point parsers call before appending
// req.Args to their argv. It looks up the registered policy, runs
// policy.ApplyArgs, logs any dropped flags via the supplied logger
// (or slog.Default() when nil), and returns the filtered args plus the
// validator error (when any).
//
// Callers MUST surface a non-nil error as a structured InvalidArgument
// failure to the daemon — not silently treat it as "drop". A validator
// rejection means the caller deliberately tried something that pattern-
// matches the policy but failed the value check; that is the strongest
// adversarial signal in the surface and it deserves a hard error.
func ApplyPolicy(toolName string, args []string, log *slog.Logger) ([]string, error) {
	if log == nil {
		log = slog.Default()
	}
	p, _ := LookupArgsPolicy(toolName)
	out, dropped, err := policy.ApplyArgs(args, p)
	for _, d := range dropped {
		log.Warn("tool.flag.denied",
			"tool", toolName,
			"flag", d.Flag,
			"value", d.Value,
			"reason", d.Reason,
		)
	}
	if err != nil {
		log.Warn("tool.flag.value_rejected",
			"tool", toolName,
			"error", err.Error(),
		)
		return nil, err
	}
	return out, nil
}

// Lookup returns the parser for a tool name. Second return is false if the
// parser is not registered; callers surface TOOL_NOT_REGISTERED.
func Lookup(name string) (Parser, bool) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := parsers[name]
	return p, ok
}

// Catalog returns every registered parser's CatalogEntry, sorted by name so
// --list-tools output is stable and easy to diff across releases.
func Catalog() []CatalogEntry {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]CatalogEntry, 0, len(registry))
	for _, p := range registry {
		out = append(out, p.Describe())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
