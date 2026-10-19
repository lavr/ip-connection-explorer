package main

import (
	"fmt"
	"io"
	"os"
)

var (
	version = "dev"
	commit  = "none"
)

const (
	exitOK        = 0
	exitRuntime   = 1
	exitUsage     = 2
	exitPreflight = 3
	exitLocked    = 4
)

const usage = `usage: ipcx <command> [flags]

commands:
  collect   observe network dependencies on this host
  merge     merge checkpoint files from several hosts
  report    print dependencies as CSV or JSON

flags:
  --version print version and exit
`

func main() {
	os.Exit(run(os.Args, os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) < 2 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	switch args[1] {
	case "--version", "-version", "version":
		fmt.Fprintf(stdout, "ipcx %s (%s)\n", version, commit)
		return exitOK
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return exitOK
	case "collect":
		return runCollect(args[2:], stdout, stderr)
	case "merge":
		return runMerge(args[2:], stdout, stderr)
	case "report":
		return runReport(args[2:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "ipcx: unknown command %q\n\n%s", args[1], usage)
		return exitUsage
	}
}
