// Package subfinder wraps ProjectDiscovery's subdomain discovery tool.
// Emits Domain + Subdomain taxonomy nodes.
package subfinder

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	graphragpb "github.com/zero-day-ai/sdk/api/gen/gibson/graphrag/v1"
	"google.golang.org/protobuf/proto"

	"github.com/zero-day-ai/gibson-tool-runner/internal/registry"
)

const (
	toolName       = "subfinder"
	toolVersion    = "0.1.0"
	defaultTimeout = 300
)

func init() { registry.Register(&parser{}) }

type parser struct{}

func (p *parser) Describe() registry.CatalogEntry {
	return registry.CatalogEntry{
		Name:        toolName,
		Version:     toolVersion,
		Description: "Passive subdomain discovery (ProjectDiscovery subfinder). Emits Domain/Subdomain nodes.",
		Tags:        []string{"recon", "dns", "discovery"},
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"target": map[string]any{"type": "string", "description": "Root domain to enumerate subdomains for."},
				"args":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
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

type subfinderRecord struct {
	Host   string `json:"host"`
	Source string `json:"source"`
}

func (p *parser) Execute(ctx context.Context, req registry.ExecuteRequest) (*registry.ExecuteResponse, error) {
	if req.Target == "" {
		return &registry.ExecuteResponse{ParseQuality: registry.ParseQualityFailed}, fmt.Errorf("subfinder: target is required")
	}
	args := []string{"-json", "-silent", "-d", req.Target}
	filtered, policyErr := registry.ApplyPolicy(toolName, req.Args, nil)
	if policyErr != nil {
		return &registry.ExecuteResponse{ParseQuality: registry.ParseQualityFailed},
			fmt.Errorf("subfinder args policy: %w", policyErr)
	}
	args = append(args, filtered...)

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "subfinder", args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	resp := &registry.ExecuteResponse{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if cmd.ProcessState != nil {
		resp.ExitCode = int32(cmd.ProcessState.ExitCode())
	}
	disc, quality, parseErr := parseJSONLines(stdout.Bytes(), req.Target)
	resp.Discovery = disc
	resp.ParseQuality = quality
	if runErr != nil && len(stdout.Bytes()) == 0 {
		resp.ParseQuality = registry.ParseQualityFailed
		return resp, fmt.Errorf("subfinder exec: %w", runErr)
	}
	return resp, parseErr
}

func parseJSONLines(raw []byte, rootDomain string) (*graphragpb.DiscoveryResult, registry.ParseQuality, error) {
	disc := &graphragpb.DiscoveryResult{}
	// Root Domain node.
	domainID := fmt.Sprintf("domain:%s", rootDomain)
	disc.Domains = append(disc.Domains, &graphragpb.Domain{
		Id:   &domainID,
		Name: rootDomain,
	})

	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	lines := 0
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var r subfinderRecord
		if err := json.Unmarshal(line, &r); err != nil {
			return disc, registry.ParseQualityPartial, fmt.Errorf("line %d: %w", lines+1, err)
		}
		lines++
		subID := fmt.Sprintf("subdomain:%s", r.Host)
		fullName := r.Host
		disc.Subdomains = append(disc.Subdomains, &graphragpb.Subdomain{
			Id:       &subID,
			DomainId: domainID,
			Name:     r.Host,
			FullName: &fullName,
		})
	}
	if err := sc.Err(); err != nil {
		return disc, registry.ParseQualityPartial, err
	}
	return disc, registry.ParseQualityStructured, nil
}
