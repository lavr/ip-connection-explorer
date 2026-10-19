package main

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/pprof"
)

func startCPUProfile(path string) (func(), error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	if err := pprof.StartCPUProfile(f); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		pprof.StopCPUProfile()
		f.Close()
	}, nil
}

func writeHeapProfile(path string, stderr io.Writer) {
	f, err := os.Create(path)
	if err != nil {
		fmt.Fprintf(stderr, "ipcx collect: --memprofile: %v\n", err)
		return
	}
	defer f.Close()
	runtime.GC()
	if err := pprof.WriteHeapProfile(f); err != nil {
		fmt.Fprintf(stderr, "ipcx collect: --memprofile: %v\n", err)
	}
}
