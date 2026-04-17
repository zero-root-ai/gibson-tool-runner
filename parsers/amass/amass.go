// Package amass wraps OWASP Amass's subdomain + asset enumerator.
// Amass emits line-delimited JSON with `name` + `addresses`; we map to
// Domain + Subdomain + Host nodes.
package amass

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
	toolName       = "amass"
	toolVersion    = "0.1.0"
	defaultTimeout = 600
)

func init() { registry.Register(&parser{}) }

type parser struct{}

func (p *parser) Describe() registry.CatalogEntry {
	return registry.CatalogEntry{
		Name:                  toolName,
		Version:               toolVersion,
		Description:           "Subdomain + asset enumeration (OWASP Amass). Emits Domain/Subdomain/Host nodes.",
		Tags:                  []string{"recon", "dns", "discovery"},
		InputSchema:           map[string]any{"type": "object", "properties": map[string]any{"target": map[string]any{"type": "string"}}, "required": []any{"target"}},
		OutputProtoType:       "gibson.graphrag.v1.DiscoveryResult",
		DefaultParseQuality:   registry.ParseQualityStructured,
		Resources:             registry.ResourceHint{VCPU: 2, Memory: "1Gi"},
		DefaultTimeoutSeconds: defaultTimeout,
	}
}

func (p *parser) OutputMessage() proto.Message { return nil }

type amassAddress struct {
	IP string `json:"ip"`
}

type amassRecord struct {
	Name      string         `json:"name"`
	Domain    string         `json:"domain"`
	Addresses []amassAddress `json:"addresses"`
}

func (p *parser) Execute(ctx context.Context, req registry.ExecuteRequest) (*registry.ExecuteResponse, error) {
	if req.Target == "" {
		return &registry.ExecuteResponse{ParseQuality: registry.ParseQualityFailed}, fmt.Errorf("amass: target is required")
	}
	args := []string{"enum", "-passive", "-json", "/dev/stdout", "-d", req.Target}
	args = append(args, req.Args...)
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "amass", args...)
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
		return resp, fmt.Errorf("amass exec: %w", runErr)
	}
	return resp, parseErr
}

func parseJSONLines(raw []byte, rootDomain string) (*graphragpb.DiscoveryResult, registry.ParseQuality, error) {
	disc := &graphragpb.DiscoveryResult{}
	domainID := fmt.Sprintf("domain:%s", rootDomain)
	disc.Domains = append(disc.Domains, &graphragpb.Domain{Id: &domainID, Name: rootDomain})

	seenHosts := map[string]bool{}
	seenSubs := map[string]bool{}

	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	lines := 0
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var r amassRecord
		if err := json.Unmarshal(line, &r); err != nil {
			return disc, registry.ParseQualityPartial, fmt.Errorf("line %d: %w", lines+1, err)
		}
		lines++
		if r.Name != "" && !seenSubs[r.Name] {
			seenSubs[r.Name] = true
			subID := fmt.Sprintf("subdomain:%s", r.Name)
			fullName := r.Name
			disc.Subdomains = append(disc.Subdomains, &graphragpb.Subdomain{
				Id: &subID, DomainId: domainID, Name: r.Name, FullName: &fullName,
			})
		}
		for _, a := range r.Addresses {
			if a.IP == "" || seenHosts[a.IP] {
				continue
			}
			seenHosts[a.IP] = true
			hostID := fmt.Sprintf("host:%s", a.IP)
			hn := r.Name
			h := &graphragpb.Host{Id: &hostID, Ip: a.IP}
			if hn != "" {
				h.Hostname = &hn
			}
			disc.Hosts = append(disc.Hosts, h)
		}
	}
	if err := sc.Err(); err != nil {
		return disc, registry.ParseQualityPartial, err
	}
	return disc, registry.ParseQualityStructured, nil
}
