package main

import (
	"bytes"
	"io"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestCollectFlagErrors(t *testing.T) {
	for _, args := range [][]string{
		{"ipcx", "collect", "--duration", "0"},
		{"ipcx", "collect", "--go-memory-limit", "12XB"},
		{"ipcx", "collect", "--checkpoint", "bogus"},
		{"ipcx", "collect", "extra-arg"},
	} {
		if code := run(args, io.Discard, io.Discard); code != 2 {
			t.Errorf("%v: code=%d", args, code)
		}
	}
}

func TestParseSize(t *testing.T) {
	ok := map[string]int64{"512MiB": 512 << 20, "1GiB": 1 << 30, "64KiB": 64 << 10, "1000": 1000}
	for in, want := range ok {
		if got, err := parseSize(in); err != nil || got != want {
			t.Errorf("%s: %d %v", in, got, err)
		}
	}
	for _, in := range []string{"", "12XB", "-1MiB", "MiB"} {
		if _, err := parseSize(in); err == nil {
			t.Errorf("%s accepted", in)
		}
	}
}

func TestCollectCheckOnNonLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("covered by integration tests on linux")
	}
	var out bytes.Buffer
	code := run([]string{"ipcx", "collect", "--check", "--state-dir", t.TempDir()}, &out, io.Discard)
	if code != 3 || !strings.Contains(out.String(), "fail") || !strings.Contains(out.String(), "unsupported platform") {
		t.Fatalf("code=%d out=%s", code, out.String())
	}
}

func TestCollectWritesProfiles(t *testing.T) {
	dir := t.TempDir()
	cpu, mem := dir+"/cpu.pprof", dir+"/mem.pprof"
	run([]string{"ipcx", "collect", "--check", "--state-dir", dir, "--cpuprofile", cpu, "--memprofile", mem}, io.Discard, io.Discard)
	for _, p := range []string{cpu, mem} {
		if st, err := os.Stat(p); err != nil || st.Size() == 0 {
			t.Fatalf("%s: %v", p, err)
		}
	}
}
