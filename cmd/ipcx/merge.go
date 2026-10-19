package main

import (
	"fmt"
	"io"

	"github.com/lavr/ip-connection-explorer/internal/checkpoint"
	"github.com/lavr/ip-connection-explorer/internal/merge"
)

const mergeUsage = "usage: ipcx merge FILE... -o OUTPUT\n"

func runMerge(args []string, stdout, stderr io.Writer) int {
	var inputs []string
	out := ""
	for i := 0; i < len(args); i++ {
		switch a := args[i]; a {
		case "-o", "--output", "-output":
			if i+1 >= len(args) {
				fmt.Fprint(stderr, mergeUsage)
				return exitUsage
			}
			out = args[i+1]
			i++
		case "-h", "--help":
			fmt.Fprint(stdout, mergeUsage)
			return exitOK
		default:
			inputs = append(inputs, a)
		}
	}
	if len(inputs) == 0 || out == "" {
		fmt.Fprint(stderr, mergeUsage)
		return exitUsage
	}
	var files []*checkpoint.File
	for _, p := range inputs {
		var probe struct {
			Kind string `json:"kind"`
		}
		if err := checkpoint.ReadJSON(p, &probe); err != nil {
			fmt.Fprintf(stderr, "ipcx merge: %v\n", err)
			return exitRuntime
		}
		if probe.Kind == merge.Kind {
			fmt.Fprintf(stderr, "ipcx merge: %s is already a merged file; merge the original checkpoints\n", p)
			return exitRuntime
		}
		f, err := checkpoint.Read(p)
		if err != nil {
			fmt.Fprintf(stderr, "ipcx merge: %v\n", err)
			return exitRuntime
		}
		files = append(files, f)
	}
	m, err := merge.Merge(files)
	if err != nil {
		fmt.Fprintf(stderr, "ipcx merge: %v\n", err)
		return exitRuntime
	}
	if err := checkpoint.WriteTo(out, m); err != nil {
		fmt.Fprintf(stderr, "ipcx merge: %v\n", err)
		return exitRuntime
	}
	fmt.Fprintf(stderr, "merged %d runs, %d dependencies, %d conflicts into %s\n", len(m.Runs), len(m.Dependencies), len(m.Conflicts), out)
	return exitOK
}
