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
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

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

func runDefault() {
	toolName := strings.TrimSpace(os.Getenv(envToolName))
	if toolName == "" {
		fmt.Fprintf(os.Stderr, "%s not set\n", envToolName)
		os.Exit(exitInputParse)
	}
	parser, ok := registry.Lookup(toolName)
	if !ok {
		fmt.Fprintf(os.Stderr, "tool %q not registered in this runner image\n", toolName)
		os.Exit(exitToolNotRegistered)
	}

	// v0.1 scaffold: input decoding + ABI marker emission will land with the
	// first parser (nmap) in task 6. For now main() returns cleanly to
	// confirm the binary compiles and --list-tools exercises the registry.
	_ = parser
	_ = context.Background
	_ = envInputB64
	fmt.Fprintln(os.Stderr, "gibson-runner: execute mode requires at least one registered parser (add parsers under ./parsers/)")
	os.Exit(exitExecuteError)
}

// healthAddr returns the listen address for the health HTTP server.
// It honours RUNNER_HEALTH_ADDR, defaulting to ":8081".
func healthAddr() string {
	if addr := os.Getenv(envHealthAddr); addr != "" {
		return addr
	}
	return ":8081"
}
