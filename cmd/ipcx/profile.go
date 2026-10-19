package main

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/pprof"
)

// createPrivate refuses an existing path, so a root run never follows a planted symlink.
func createPrivate(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
}

func startCPUProfile(path string) (func(), error) {
	f, err := createPrivate(path)
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
	f, err := createPrivate(path)
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
