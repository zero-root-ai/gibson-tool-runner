// Command gibson-runner is the entry point executed inside a Setec microVM to
// dispatch a single Gibson tool call, or (with --list-tools) emit the JSON
// catalog of every parser compiled into this binary.
//
// Three modes:
//
//	gibson-runner --list-tools
//	    Print a JSON array of CatalogEntry objects to stdout, exit 0.
//	    The Gibson daemon's catalog refresher ingests this to populate
//	    ComponentRegistry entries — adding a tool never requires a daemon
//	    restart or Helm change.
//
//	gibson-runner --serve
//	    Run as a long-lived deployment service. Initialises OTel observability
//	    and starts an HTTP health server (default :8081) exposing /readyz and
//	    /healthz. Blocks until SIGTERM/SIGINT.
//	    Use this mode in Kubernetes deployments.
//
//	gibson-runner
//	    Default. Reads GIBSON_TOOL_NAME from env, looks up its registered
//	    parser, reads GIBSON_TOOL_INPUT_B64 for the typed request, executes,
//	    and emits the response via the standard tool-runner ABI marker on
//	    stdout. Exit codes: 0 success, 1 input parse error, 2 execute error,
//	    3 output marshal error, 4 tool not registered.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	componentpb "github.com/zero-day-ai/sdk/api/gen/gibson/component/v1"
	graphragpb "github.com/zero-day-ai/sdk/api/gen/gibson/graphrag/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/zero-day-ai/gibson-tool-runner/internal/probes"
	"github.com/zero-day-ai/gibson-tool-runner/internal/registry"
	"github.com/zero-day-ai/platform-clients/observability"
	"github.com/zero-day-ai/platform-clients/readiness"

	// Blank-import every parser package so its init() registers with the
	// central parser registry. The list grows as parsers land.
	_ "github.com/zero-day-ai/gibson-tool-runner/parsers/amass"
	_ "github.com/zero-day-ai/gibson-tool-runner/parsers/dnsx"
	_ "github.com/zero-day-ai/gibson-tool-runner/parsers/httpx"
	_ "github.com/zero-day-ai/gibson-tool-runner/parsers/masscan"
	_ "github.com/zero-day-ai/gibson-tool-runner/parsers/naabu"
	_ "github.com/zero-day-ai/gibson-tool-runner/parsers/nmap"
	_ "github.com/zero-day-ai/gibson-tool-runner/parsers/nuclei"
	_ "github.com/zero-day-ai/gibson-tool-runner/parsers/subfinder"
)

const (
	envToolName = "GIBSON_TOOL_NAME"
	envInputB64 = "GIBSON_TOOL_INPUT_B64"

	// envHealthAddr is the listen address for the health HTTP server in --serve
	// mode. Defaults to ":8081" (non-privileged port; configurable so tests
	// can bind to :0).
	envHealthAddr = "RUNNER_HEALTH_ADDR"

	// serviceName is the OTel service.name attribute for this binary.
	serviceName = "gibson-tool-runner"

	exitOK              = 0
	exitInputParse      = 1
	exitExecuteError    = 2
	exitOutputMarshal   = 3
	exitToolNotRegistered = 4
)

func main() {
	listTools := flag.Bool("list-tools", false, "Emit the JSON catalog of every parser compiled into this binary and exit.")
	serve := flag.Bool("serve", false, "Run as a long-lived service, starting the health HTTP server. Use in Kubernetes deployments.")
	flag.Parse()

	if *listTools {
		runListTools()
		return
	}
	if *serve {
		runServe()
		return
	}
	runDefault()
}

func runListTools() {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(registry.Catalog()); err != nil {
		fmt.Fprintf(os.Stderr, "encode catalog: %v\n", err)
		os.Exit(1)
	}
}

// runServe starts OTel observability, wires the readiness aggregator with a
// daemon-reachability probe, and blocks on the health HTTP server until
// SIGTERM or SIGINT.
//
// Trace context propagation: observability.Init registers the global OTel
// W3C TraceContext + Baggage propagators. When the daemon stamps outgoing tool
// invocations with a traceparent header, gRPC interceptors and context-aware
// libraries transparently propagate the mission trace ID into every child span
// started inside this process — giving end-to-end visibility from the
// mission's LLM-decision span through to the tool-execution span.
func runServe() {
	// Initialise OTel. The call is idempotent; OTEL_EXPORTER_OTLP_ENDPOINT
	// controls whether traces are exported (no-op when unset so local runs
	// stay quiet without a collector).
	otelProvider, err := observability.Init(serviceName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "observability init: %v\n", err)
		os.Exit(1)
	}

	logger := otelProvider.Logger
	logger.Info("gibson-tool-runner starting", "mode", "serve")

	// Readiness aggregator — daemon-callback reachability probe.
	agg := readiness.NewAggregator()
	agg.Register(probes.NewDaemonProbe(0))

	// Health HTTP server.
	addr := healthAddr()
	mux := http.NewServeMux()
	mux.Handle("/readyz", agg.ReadyHandler())
	mux.Handle("/healthz", agg.LivenessHandler())

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Serve in the background; block until signal.
	go func() {
		logger.Info("health server listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("health server error", "error", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	<-quit

	logger.Info("shutting down")

	// Graceful HTTP shutdown.
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutCancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		logger.Warn("health server shutdown error", "error", err)
	}

	// Flush buffered OTel spans and metrics.
	flushCtx, flushCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer flushCancel()
	if err := otelProvider.Shutdown(flushCtx); err != nil {
		logger.Warn("otel shutdown error", "error", err)
	}

	logger.Info("shutdown complete")
}

// abiOutputMarker and abiErrorMarker are the ABI sentinel prefixes the daemon
// parses from the last stdout line to extract the b64-encoded response or error.
const (
	abiOutputMarker = "===GIBSON_TOOL_OUTPUT==="
	abiErrorMarker  = "===GIBSON_TOOL_ERROR==="
)

func runDefault() {
	toolName := strings.TrimSpace(os.Getenv(envToolName))
	if toolName == "" {
		fmt.Fprintf(os.Stderr, "%s not set\n", envToolName)
		os.Exit(exitInputParse)
	}
	parser, ok := registry.Lookup(toolName)
	if !ok {
		emitError(fmt.Sprintf("tool %q not registered in this runner image", toolName))
		os.Exit(exitToolNotRegistered)
	}

	// Decode the request envelope from GIBSON_TOOL_INPUT_B64.
	inputB64 := strings.TrimSpace(os.Getenv(envInputB64))
	if inputB64 == "" {
		fmt.Fprintf(os.Stderr, "%s not set\n", envInputB64)
		os.Exit(exitInputParse)
	}
	raw, err := base64.StdEncoding.DecodeString(inputB64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "base64 decode %s: %v\n", envInputB64, err)
		os.Exit(exitInputParse)
	}
	var callReq componentpb.CallToolRequest
	if err := protojson.Unmarshal(raw, &callReq); err != nil {
		fmt.Fprintf(os.Stderr, "protojson unmarshal CallToolRequest: %v\n", err)
		os.Exit(exitInputParse)
	}

	// Map CallToolRequest.input_json into the internal ExecuteRequest.
	execReq, err := decodeInputJSON(callReq.GetInputJson())
	if err != nil {
		fmt.Fprintf(os.Stderr, "decode input_json: %v\n", err)
		os.Exit(exitInputParse)
	}
	if callReq.GetTimeoutMs() > 0 {
		execReq.Timeout = int32(callReq.GetTimeoutMs() / 1000)
	}

	// Root context: honour SIGTERM/SIGINT so the process exits cleanly when
	// the microVM supervisor terminates it.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// Per-call timeout on top of the signal context.
	if execReq.Timeout > 0 {
		var timeoutCancel context.CancelFunc
		ctx, timeoutCancel = context.WithTimeout(ctx, time.Duration(execReq.Timeout)*time.Second)
		defer timeoutCancel()
	}

	resp, execErr := parser.Execute(ctx, execReq)
	if execErr != nil {
		// The error is surfaced via CallToolResponse.error so the daemon can
		// log it as a structured outcome. We also preserve stdout/stderr from
		// resp when the parser populated them (e.g. nmap produces useful stderr
		// even on partial failure).
		code := "EXECUTE_ERROR"
		if resp != nil && resp.ParseQuality == registry.ParseQualityFailed {
			code = "PARSE_FAILED"
		}
		emitResponse(&componentpb.CallToolResponse{
			Error: &componentpb.ComponentError{
				Code:      code,
				Message:   execErr.Error(),
				Retryable: false,
			},
		})
		os.Exit(exitExecuteError)
	}

	// Marshal the DiscoveryResult as protojson into output_json. When there
	// is no discovery (e.g. the tool produced raw output only), emit an empty
	// DiscoveryResult so the daemon's JSON parser always gets a valid object.
	disc := resp.Discovery
	if disc == nil {
		disc = &graphragpb.DiscoveryResult{}
	}
	outputJSON, err := protojson.MarshalOptions{
		EmitUnpopulated: false,
		UseProtoNames:   true,
	}.Marshal(disc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal DiscoveryResult: %v\n", err)
		os.Exit(exitOutputMarshal)
	}
	emitResponse(&componentpb.CallToolResponse{
		OutputJson: string(outputJSON),
	})
}

// decodeInputJSON unmarshals the tool-specific JSON payload (input_json from
// CallToolRequest) into an ExecuteRequest. The schema is tool-defined but all
// tools share a common subset: "target" (string), "args" ([]string), and
// arbitrary string k/v pairs that land in Options.
func decodeInputJSON(inputJSON string) (registry.ExecuteRequest, error) {
	var req registry.ExecuteRequest
	if inputJSON == "" {
		return req, nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(inputJSON), &m); err != nil {
		return req, fmt.Errorf("unmarshal input_json: %w", err)
	}

	if raw, ok := m["target"]; ok {
		if err := json.Unmarshal(raw, &req.Target); err != nil {
			return req, fmt.Errorf("input_json.target: %w", err)
		}
		delete(m, "target")
	}

	if raw, ok := m["args"]; ok {
		if err := json.Unmarshal(raw, &req.Args); err != nil {
			return req, fmt.Errorf("input_json.args: %w", err)
		}
		delete(m, "args")
	}

	// Remaining fields become Options (string values only; non-strings are
	// skipped — parsers that need structured types handle them directly).
	if len(m) > 0 {
		req.Options = make(map[string]string, len(m))
	}
	for k, raw := range m {
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			req.Options[k] = s
		}
	}
	return req, nil
}

// emitResponse marshals resp as protojson, base64-encodes it, and prints
// the ABI output marker line to stdout.
func emitResponse(resp *componentpb.CallToolResponse) {
	b, err := protojson.Marshal(resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal CallToolResponse: %v\n", err)
		os.Exit(exitOutputMarshal)
	}
	fmt.Printf("%s%s\n", abiOutputMarker, base64.StdEncoding.EncodeToString(b))
}

// emitError writes the ABI error marker and message to stdout. The caller is
// responsible for calling os.Exit with the appropriate code.
func emitError(msg string) {
	fmt.Printf("%s%s\n", abiErrorMarker, msg)
}

// healthAddr returns the listen address for the health HTTP server.
// It honours RUNNER_HEALTH_ADDR, defaulting to ":8081".
func healthAddr() string {
	if addr := os.Getenv(envHealthAddr); addr != "" {
		return addr
	}
	return ":8081"
}
