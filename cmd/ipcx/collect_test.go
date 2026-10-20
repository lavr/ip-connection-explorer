package main

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestCollectFlagErrors(t *testing.T) {
	for _, args := range [][]string{
		{"ipcx", "collect", "--duration", "-1h"},
		{"ipcx", "collect", "--prometheus-exporter.ttl", "0"},
		{"ipcx", "collect", "--prometheus-exporter.max-series", "0"},
		{"ipcx", "collect", "--prometheus-exporter.path", "metrics"},
		{"ipcx", "collect", "--prometheus-exporter.listen", "127.0.0.1:0", "--raw"},
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

func TestProfileRefusesExistingPath(t *testing.T) {
	p := t.TempDir() + "/cpu.pprof"
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"ipcx", "collect", "--check", "--state-dir", t.TempDir(), "--cpuprofile", p}, io.Discard, io.Discard); code != 2 {
		t.Fatalf("code=%d", code)
	}
	if st, _ := os.Stat(t.TempDir()); st == nil {
		t.Fatal()
	}
}

func TestProfileFileIsPrivate(t *testing.T) {
	p := t.TempDir() + "/cpu.pprof"
	run([]string{"ipcx", "collect", "--check", "--state-dir", t.TempDir(), "--cpuprofile", p}, io.Discard, io.Discard)
	st, err := os.Stat(p)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", st.Mode(), err)
	}
}

func TestCollectExporterBindFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var errOut bytes.Buffer
	code := run([]string{"ipcx", "collect", "--state-dir", t.TempDir(), "--prometheus-exporter.listen", ln.Addr().String()}, io.Discard, &errOut)
	if code != 3 || !strings.Contains(errOut.String(), "--prometheus-exporter.listen") {
		t.Fatalf("code=%d err=%s", code, errOut.String())
	}
}

func TestCollectCheckDoesNotServe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var errOut bytes.Buffer
	run([]string{"ipcx", "collect", "--check", "--state-dir", t.TempDir(), "--prometheus-exporter.listen", ln.Addr().String()}, io.Discard, &errOut)
	if strings.Contains(errOut.String(), "prometheus-exporter") {
		t.Fatalf("--check touched the exporter: %s", errOut.String())
	}
}

func TestExporterServerServesPathOnly(t *testing.T) {
	ms, err := startMetricsServer("127.0.0.1:0", "/metrics", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok\n")
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer ms.close()
	base := "http://" + ms.addr.String()
	for path, want := range map[string]int{"/metrics": 200, "/": 404, "/debug/pprof/": 404} {
		resp, err := http.Get(base + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("%s: %d", path, resp.StatusCode)
		}
	}
}
