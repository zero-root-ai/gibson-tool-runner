// Package naabu wraps ProjectDiscovery's naabu port scanner.
// Emits Host + Port nodes for each discovered open port.
package naabu

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
	toolName       = "naabu"
	toolVersion    = "0.1.0"
	defaultTimeout = 300
)

func init() { registry.Register(&parser{}) }

type parser struct{}

func (p *parser) Describe() registry.CatalogEntry {
	return registry.CatalogEntry{
		Name:                  toolName,
		Version:               toolVersion,
		Description:           "Fast port scanner (ProjectDiscovery naabu). Emits Host/Port nodes for each open port.",
		Tags:                  []string{"recon", "network"},
		InputSchema:           map[string]any{"type": "object", "properties": map[string]any{"target": map[string]any{"type": "string"}, "ports": map[string]any{"type": "string"}}, "required": []any{"target"}},
		OutputProtoType:       "gibson.graphrag.v1.DiscoveryResult",
		DefaultParseQuality:   registry.ParseQualityStructured,
		Resources:             registry.ResourceHint{VCPU: 2, Memory: "512Mi"},
		DefaultTimeoutSeconds: defaultTimeout,
	}
}

func (p *parser) OutputMessage() proto.Message { return nil }

type naabuRecord struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

func (p *parser) Execute(ctx context.Context, req registry.ExecuteRequest) (*registry.ExecuteResponse, error) {
	if req.Target == "" {
		return &registry.ExecuteResponse{ParseQuality: registry.ParseQualityFailed}, fmt.Errorf("naabu: target is required")
	}
	args := []string{"-json", "-silent", "-host", req.Target}
	if ports := req.Options["ports"]; ports != "" {
		args = append(args, "-p", ports)
	}
	filtered, policyErr := registry.ApplyPolicy(toolName, req.Args, nil)
	if policyErr != nil {
		return &registry.ExecuteResponse{ParseQuality: registry.ParseQualityFailed},
			fmt.Errorf("naabu args policy: %w", policyErr)
	}
	args = append(args, filtered...)

	sbCfg := sandbox.DefaultConfig()
	var stdout, stderr sandbox.CappedBuffer
	stdout.Init(sbCfg.OutputCapBytes)
	stderr.Init(sbCfg.OutputCapBytes)
	cmd := exec.CommandContext(ctx, "naabu", args...)
	sandbox.Apply(cmd, sbCfg)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	resp := &registry.ExecuteResponse{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if cmd.ProcessState != nil {
		resp.ExitCode = int32(cmd.ProcessState.ExitCode())
	}
	if err := stdout.Err(); err != nil {
		return resp, fmt.Errorf("naabu stdout: %w", err)
	}
	disc, quality, parseErr := parseJSONLines(stdout.Bytes())
	resp.Discovery = disc
	resp.ParseQuality = quality
	if runErr != nil && len(stdout.Bytes()) == 0 {
		resp.ParseQuality = registry.ParseQualityFailed
		return resp, fmt.Errorf("naabu exec: %w", runErr)
	}
	return resp, parseErr
}

func parseJSONLines(raw []byte) (*graphragpb.DiscoveryResult, registry.ParseQuality, error) {
	disc := &graphragpb.DiscoveryResult{}
	hostsByIP := map[string]string{} // ip → host_id

	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	lines := 0
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var r naabuRecord
		if err := json.Unmarshal(line, &r); err != nil {
			return disc, registry.ParseQualityPartial, fmt.Errorf("line %d: %w", lines+1, err)
		}
		lines++
		hostID, seen := hostsByIP[r.IP]
		if !seen {
			hostID = fmt.Sprintf("host:%s", r.IP)
			hostsByIP[r.IP] = hostID
			hn := r.Host
			h := &graphragpb.Host{Id: &hostID, Ip: r.IP}
			if r.Host != "" {
				h.Hostname = &hn
			}
			disc.Hosts = append(disc.Hosts, h)
		}
		portID := fmt.Sprintf("%s:port:tcp/%d", hostID, r.Port)
		disc.Ports = append(disc.Ports, &graphragpb.Port{
			Id:       &portID,
			HostId:   hostID,
			Number:   int32(r.Port),
			Protocol: "tcp",
		})
	}
	if err := sc.Err(); err != nil {
		return disc, registry.ParseQualityPartial, err
	}
	return disc, registry.ParseQualityStructured, nil
}
