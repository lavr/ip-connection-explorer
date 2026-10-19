package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/lavr/ip-connection-explorer/internal/model"
	"github.com/lavr/ip-connection-explorer/internal/report"
)

func runReport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "csv", "output format: csv or json")
	role := fs.String("role", "all", "rows to show: known, unknown (includes conflict) or all")
	minConf := fs.String("min-confidence", "low", "lowest confidence to show: low, medium or high")
	hidden := fs.Bool("include-hidden", false, "also show loopback, forwarded and unresolved rows")
	var path string
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		path, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if path == "" && fs.NArg() == 1 {
		path = fs.Arg(0)
	} else if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "ipcx report: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}
	if path == "" {
		fmt.Fprintln(stderr, "usage: ipcx report FILE [--format csv|json] [--role known|unknown|all] [--min-confidence low|medium|high] [--include-hidden]")
		return exitUsage
	}
	var conf model.Confidence
	if err := conf.UnmarshalText([]byte(*minConf)); err != nil {
		fmt.Fprintf(stderr, "ipcx report: --min-confidence: %v\n", err)
		return exitUsage
	}
	if *format != "csv" && *format != "json" {
		fmt.Fprintf(stderr, "ipcx report: --format must be csv or json\n")
		return exitUsage
	}
	if *role != "known" && *role != "unknown" && *role != "all" {
		fmt.Fprintf(stderr, "ipcx report: --role must be known, unknown or all\n")
		return exitUsage
	}
	in, err := report.Load(path)
	if err != nil {
		fmt.Fprintf(stderr, "ipcx report: %v\n", err)
		return exitRuntime
	}
	if err := report.Write(stdout, stderr, in, report.Options{Format: *format, Role: *role, MinConfidence: conf, IncludeHidden: *hidden}); err != nil {
		fmt.Fprintf(stderr, "ipcx report: %v\n", err)
		return exitRuntime
	}
	return exitOK
}
