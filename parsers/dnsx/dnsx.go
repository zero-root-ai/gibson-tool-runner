// Package dnsx wraps ProjectDiscovery's dnsx DNS toolkit.
// Emits Host + Subdomain nodes for each resolved record.
package dnsx

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
	"github.com/zero-day-ai/gibson-tool-runner/internal/sandbox"
)

const (
	toolName       = "dnsx"
	toolVersion    = "0.1.0"
	defaultTimeout = 300
)

func init() { registry.Register(&parser{}) }

type parser struct{}

func (p *parser) Describe() registry.CatalogEntry {
	return registry.CatalogEntry{
		Name:                  toolName,
		Version:               toolVersion,
		Description:           "DNS resolver + record enumerator (ProjectDiscovery dnsx). Emits Host nodes for resolved A/AAAA records.",
		Tags:                  []string{"recon", "dns"},
		InputSchema:           map[string]any{"type": "object", "properties": map[string]any{"target": map[string]any{"type": "string"}}, "required": []any{"target"}},
		OutputProtoType:       "gibson.graphrag.v1.DiscoveryResult",
		DefaultParseQuality:   registry.ParseQualityStructured,
		Resources:             registry.ResourceHint{VCPU: 1, Memory: "256Mi"},
		DefaultTimeoutSeconds: defaultTimeout,
	}
}

func (p *parser) OutputMessage() proto.Message { return nil }

type dnsxRecord struct {
	Host string   `json:"host"`
	A    []string `json:"a"`
	AAAA []string `json:"aaaa"`
}

func (p *parser) Execute(ctx context.Context, req registry.ExecuteRequest) (*registry.ExecuteResponse, error) {
	if req.Target == "" {
		return &registry.ExecuteResponse{ParseQuality: registry.ParseQualityFailed}, fmt.Errorf("dnsx: target is required")
	}
	args := []string{"-json", "-silent", "-l", "/dev/stdin", "-a", "-aaaa"}
	filtered, policyErr := registry.ApplyPolicy(toolName, req.Args, nil)
	if policyErr != nil {
		return &registry.ExecuteResponse{ParseQuality: registry.ParseQualityFailed},
			fmt.Errorf("dnsx args policy: %w", policyErr)
	}
	args = append(args, filtered...)
	sbCfg := sandbox.DefaultConfig()
	var stdout, stderr sandbox.CappedBuffer
	stdout.Init(sbCfg.OutputCapBytes)
	stderr.Init(sbCfg.OutputCapBytes)
	cmd := exec.CommandContext(ctx, "dnsx", args...)
	sandbox.Apply(cmd, sbCfg)
	cmd.Stdin = bytes.NewReader([]byte(req.Target + "\n"))
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	resp := &registry.ExecuteResponse{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if cmd.ProcessState != nil {
		resp.ExitCode = int32(cmd.ProcessState.ExitCode())
	}
	if err := stdout.Err(); err != nil {
		return resp, fmt.Errorf("dnsx stdout: %w", err)
	}
	disc, quality, parseErr := parseJSONLines(stdout.Bytes())
	resp.Discovery = disc
	resp.ParseQuality = quality
	if runErr != nil && len(stdout.Bytes()) == 0 {
		resp.ParseQuality = registry.ParseQualityFailed
		return resp, fmt.Errorf("dnsx exec: %w", runErr)
	}
	return resp, parseErr
}

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
		var r dnsxRecord
		if err := json.Unmarshal(line, &r); err != nil {
			return disc, registry.ParseQualityPartial, fmt.Errorf("line %d: %w", lines+1, err)
		}
		lines++
		for _, ip := range r.A {
			hostID := fmt.Sprintf("host:%s", ip)
			hn := r.Host
			disc.Hosts = append(disc.Hosts, &graphragpb.Host{
				Id:       &hostID,
				Ip:       ip,
				Hostname: &hn,
			})
		}
		for _, ip := range r.AAAA {
			hostID := fmt.Sprintf("host:%s", ip)
			hn := r.Host
			disc.Hosts = append(disc.Hosts, &graphragpb.Host{
				Id:       &hostID,
				Ip:       ip,
				Hostname: &hn,
			})
		}
	}
	if err := sc.Err(); err != nil {
		return disc, registry.ParseQualityPartial, err
	}
	return disc, registry.ParseQualityStructured, nil
}
