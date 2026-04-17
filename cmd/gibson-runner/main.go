// Command gibson-runner is the entry point executed inside a Setec microVM to
// dispatch a single Gibson tool call, or (with --list-tools) emit the JSON
// catalog of every parser compiled into this binary.
//
// Two modes:
//
//	gibson-runner --list-tools
//	    Print a JSON array of CatalogEntry objects to stdout, exit 0.
//	    The Gibson daemon's catalog refresher ingests this to populate
//	    ComponentRegistry entries — adding a tool never requires a daemon
//	    restart or Helm change.
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
	"os"
	"strings"

	"github.com/zero-day-ai/gibson-tool-runner/internal/registry"

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

	exitOK               = 0
	exitInputParse       = 1
	exitExecuteError     = 2
	exitOutputMarshal    = 3
	exitToolNotRegistered = 4
)

func main() {
	listTools := flag.Bool("list-tools", false, "Emit the JSON catalog of every parser compiled into this binary and exit.")
	flag.Parse()

	if *listTools {
		runListTools()
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
