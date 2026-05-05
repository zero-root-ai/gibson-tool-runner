// Package httpx implements a Gibson tool-runner parser wrapping
// ProjectDiscovery's httpx HTTP probe + fingerprinter. It runs
// `httpx -json` and decodes the JSON-lines output into Endpoint + Service +
// Technology taxonomy nodes inside a DiscoveryResult.
package httpx

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	graphragpb "github.com/zero-day-ai/sdk/api/gen/gibson/graphrag/v1"
	"google.golang.org/protobuf/proto"

	"github.com/zero-day-ai/gibson-tool-runner/internal/registry"
)

const (
	toolName       = "httpx"
	toolVersion    = "0.1.0"
	defaultTimeout = 180
)

func init() { registry.Register(&parser{}) }

type parser struct{}

func (p *parser) Describe() registry.CatalogEntry {
	return registry.CatalogEntry{
		Name:        toolName,
		Version:     toolVersion,
		Description: "HTTP probe + fingerprinter (ProjectDiscovery httpx). Emits typed Endpoint/Service/Technology nodes.",
		Tags:        []string{"recon", "web", "fingerprint"},
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"target": map[string]any{"type": "string", "description": "URL, host, or IP. httpx accepts the same inputs via stdin; single value here is probed once."},
				"paths":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": `Paths to probe beneath the target (e.g. ["/", "/api"]).`},
				"args":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Extra httpx flags."},
			},
			"required": []any{"target"},
		},
		OutputProtoType:       "gibson.graphrag.v1.DiscoveryResult",
		DefaultParseQuality:   registry.ParseQualityStructured,
		Resources:             registry.ResourceHint{VCPU: 1, Memory: "256Mi"},
		DefaultTimeoutSeconds: defaultTimeout,
	}
}

func (p *parser) OutputMessage() proto.Message { return nil }

// httpxResult is the subset of httpx's -json output we consume. httpx emits
// many more fields; we decode only what feeds taxonomy nodes and preserve
// the rest in stdout for operators who want to inspect raw output.
type httpxResult struct {
	URL           string   `json:"url"`
	Host          string   `json:"host"`
	StatusCode    int      `json:"status_code"`
	ContentType   string   `json:"content_type"`
	ContentLength int64    `json:"content_length"`
	Title         string   `json:"title"`
	WebServer     string   `json:"webserver"`
	Tech          []string `json:"tech"`
	Scheme        string   `json:"scheme"`
	Method        string   `json:"method"`
}

func (p *parser) Execute(ctx context.Context, req registry.ExecuteRequest) (*registry.ExecuteResponse, error) {
	if req.Target == "" {
		return &registry.ExecuteResponse{ParseQuality: registry.ParseQualityFailed}, fmt.Errorf("httpx: target is required")
	}

	args := []string{"-json", "-silent", "-target", req.Target}
	if paths := req.Options["paths"]; paths != "" {
		args = append(args, "-path", paths)
	}
	filtered, policyErr := registry.ApplyPolicy(toolName, req.Args, nil)
	if policyErr != nil {
		return &registry.ExecuteResponse{ParseQuality: registry.ParseQualityFailed},
			fmt.Errorf("httpx args policy: %w", policyErr)
	}
	args = append(args, filtered...)

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "httpx", args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	resp := &registry.ExecuteResponse{
		Stdout: stdout.Bytes(),
		Stderr: stderr.Bytes(),
	}
	if cmd.ProcessState != nil {
		resp.ExitCode = int32(cmd.ProcessState.ExitCode())
	}

	disc, quality, parseErr := parseJSONLines(stdout.Bytes())
	resp.Discovery = disc
	resp.ParseQuality = quality
	if runErr != nil && len(stdout.Bytes()) == 0 {
		resp.ParseQuality = registry.ParseQualityFailed
		return resp, fmt.Errorf("httpx exec: %w", runErr)
	}
	if parseErr != nil {
		return resp, fmt.Errorf("httpx parse: %w", parseErr)
	}
	return resp, nil
}

// parseJSONLines converts httpx's -json output to a DiscoveryResult. Each
// line is one probe result. Empty input → empty DiscoveryResult + quality
// RAW (nothing to structure).
func parseJSONLines(raw []byte) (*graphragpb.DiscoveryResult, registry.ParseQuality, error) {
	disc := &graphragpb.DiscoveryResult{}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	lines := 0
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var r httpxResult
		if err := json.Unmarshal(line, &r); err != nil {
			return disc, registry.ParseQualityPartial, fmt.Errorf("line %d: %w", lines+1, err)
		}
		lines++
		appendProbe(disc, r)
	}
	if err := sc.Err(); err != nil {
		return disc, registry.ParseQualityPartial, err
	}
	if lines == 0 {
		return disc, registry.ParseQualityRaw, nil
	}
	return disc, registry.ParseQualityStructured, nil
}

func appendProbe(disc *graphragpb.DiscoveryResult, r httpxResult) {
	// Service — synthetic "http" or scheme if present.
	serviceID := fmt.Sprintf("service:%s", r.URL)
	serviceName := "http"
	if strings.ToLower(r.Scheme) == "https" {
		serviceName = "https"
	}
	svc := &graphragpb.Service{
		Id:   &serviceID,
		Name: serviceName,
	}
	if r.WebServer != "" {
		ws := r.WebServer
		svc.Product = &ws
	}
	disc.Services = append(disc.Services, svc)

	// Endpoint.
	ep := &graphragpb.Endpoint{
		ServiceId: serviceID,
		Url:       r.URL,
	}
	epID := fmt.Sprintf("endpoint:%s", r.URL)
	ep.Id = &epID
	if r.Method != "" {
		m := r.Method
		ep.Method = &m
	}
	if r.StatusCode != 0 {
		sc := int32(r.StatusCode)
		ep.StatusCode = &sc
	}
	if r.ContentType != "" {
		ct := r.ContentType
		ep.ContentType = &ct
	}
	if r.ContentLength > 0 {
		cl := r.ContentLength
		ep.ContentLength = &cl
	}
	if r.Title != "" {
		t := r.Title
		ep.Title = &t
	}
	disc.Endpoints = append(disc.Endpoints, ep)

	// Technology fingerprints.
	for _, t := range r.Tech {
		if t == "" {
			continue
		}
		parent := epID
		parentType := "endpoint"
		techID := fmt.Sprintf("tech:%s:%s", r.URL, t)
		disc.Technologies = append(disc.Technologies, &graphragpb.Technology{
			Id:         &techID,
			Name:       t,
			ParentId:   &parent,
			ParentType: &parentType,
		})
	}
}
