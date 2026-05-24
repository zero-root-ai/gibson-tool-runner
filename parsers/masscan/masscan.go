// Package masscan wraps the masscan high-speed port scanner. Masscan emits
// line-delimited JSON of the form `{"ip":..., "ports":[{"port":..., "proto":"tcp"}]}`.
// Emits Host + Port nodes.
package masscan

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
	toolName       = "masscan"
	toolVersion    = "0.1.0"
	defaultTimeout = 600
)

func init() { registry.Register(&parser{}) }

type parser struct{}

func (p *parser) Describe() registry.CatalogEntry {
	return registry.CatalogEntry{
		Name:                  toolName,
		Version:               toolVersion,
		Description:           "High-throughput port scanner (masscan). Emits Host/Port nodes for open ports across large CIDR ranges.",
		Tags:                  []string{"recon", "network", "scan"},
		InputSchema:           map[string]any{"type": "object", "properties": map[string]any{"target": map[string]any{"type": "string"}, "ports": map[string]any{"type": "string"}, "rate": map[string]any{"type": "string"}}, "required": []any{"target", "ports"}},
		OutputProtoType:       "gibson.graphrag.v1.DiscoveryResult",
		DefaultParseQuality:   registry.ParseQualityStructured,
		Resources:             registry.ResourceHint{VCPU: 4, Memory: "2Gi"},
		DefaultTimeoutSeconds: defaultTimeout,
	}
}

func (p *parser) OutputMessage() proto.Message { return nil }

type masscanPort struct {
	Port   int    `json:"port"`
	Proto  string `json:"proto"`
	Status string `json:"status"`
	Reason string `json:"reason"`
}

type masscanRecord struct {
	IP    string        `json:"ip"`
	Ports []masscanPort `json:"ports"`
}

func (p *parser) Execute(ctx context.Context, req registry.ExecuteRequest) (*registry.ExecuteResponse, error) {
	if req.Target == "" {
		return &registry.ExecuteResponse{ParseQuality: registry.ParseQualityFailed}, fmt.Errorf("masscan: target is required")
	}
	ports := req.Options["ports"]
	if ports == "" {
		ports = "1-65535"
	}
	rate := req.Options["rate"]
	if rate == "" {
		rate = "1000"
	}
	filtered, policyErr := registry.ApplyPolicy(toolName, req.Args, nil)
	if policyErr != nil {
		return &registry.ExecuteResponse{ParseQuality: registry.ParseQualityFailed},
			fmt.Errorf("masscan args policy: %w", policyErr)
	}
	args := []string{"--rate", rate, "-p", ports, "-oJ", "-", req.Target}
	args = append(args, filtered...)
	sbCfg := sandbox.DefaultConfig()
	var stdout, stderr sandbox.CappedBuffer
	stdout.Init(sbCfg.OutputCapBytes)
	stderr.Init(sbCfg.OutputCapBytes)
	cmd := exec.CommandContext(ctx, "masscan", args...)
	sandbox.Apply(cmd, sbCfg)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	resp := &registry.ExecuteResponse{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if cmd.ProcessState != nil {
		resp.ExitCode = int32(cmd.ProcessState.ExitCode())
	}
	if err := stdout.Err(); err != nil {
		return resp, fmt.Errorf("masscan stdout: %w", err)
	}
	disc, quality, parseErr := parseJSON(stdout.Bytes())
	resp.Discovery = disc
	resp.ParseQuality = quality
	if runErr != nil && len(stdout.Bytes()) == 0 {
		resp.ParseQuality = registry.ParseQualityFailed
		return resp, fmt.Errorf("masscan exec: %w", runErr)
	}
	return resp, parseErr
}

// parseJSON handles masscan's -oJ output — it emits a JSON array prefixed
// with comma-separated objects (non-strict). We handle both valid arrays
// and the streaming-friendly line-delimited form.
func parseJSON(raw []byte) (*graphragpb.DiscoveryResult, registry.ParseQuality, error) {
	disc := &graphragpb.DiscoveryResult{}
	seenHosts := map[string]string{}

	// Strip the array brackets if present, process each JSON object
	// independently. This tolerates masscan's non-standard trailing comma.
	body := bytes.TrimSpace(raw)
	body = bytes.TrimPrefix(body, []byte("["))
	body = bytes.TrimSuffix(body, []byte("]"))

	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	lines := 0
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		line = bytes.TrimSuffix(line, []byte(","))
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var r masscanRecord
		if err := json.Unmarshal(line, &r); err != nil {
			return disc, registry.ParseQualityPartial, fmt.Errorf("line %d: %w", lines+1, err)
		}
		lines++
		hostID, seen := seenHosts[r.IP]
		if !seen {
			hostID = fmt.Sprintf("host:%s", r.IP)
			seenHosts[r.IP] = hostID
			disc.Hosts = append(disc.Hosts, &graphragpb.Host{Id: &hostID, Ip: r.IP})
		}
		for _, p := range r.Ports {
			proto := p.Proto
			if proto == "" {
				proto = "tcp"
			}
			portID := fmt.Sprintf("%s:port:%s/%d", hostID, proto, p.Port)
			port := &graphragpb.Port{
				Id: &portID, HostId: hostID, Number: int32(p.Port), Protocol: proto,
			}
			if p.Status != "" {
				s := p.Status
				port.State = &s
			}
			if p.Reason != "" {
				reason := p.Reason
				port.Reason = &reason
			}
			disc.Ports = append(disc.Ports, port)
		}
	}
	if err := sc.Err(); err != nil {
		return disc, registry.ParseQualityPartial, err
	}
	return disc, registry.ParseQualityStructured, nil
}
