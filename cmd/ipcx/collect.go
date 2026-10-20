package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lavr/ip-connection-explorer/internal/collector"
	"github.com/lavr/ip-connection-explorer/internal/exporter"
	"github.com/lavr/ip-connection-explorer/internal/flows"
	"github.com/lavr/ip-connection-explorer/internal/rawlog"
)

func runCollect(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("collect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	duration := fs.String("duration", "7d", "how long to collect (e.g. 7d, 36h); 0 runs until stopped")
	stateDir := fs.String("state-dir", "/var/lib/ipcx", "directory for checkpoints and the lock file")
	ckEvery := fs.String("checkpoint", "2m", "checkpoint interval")
	dumpEvery := fs.String("dump-every", "5m", "interval between full conntrack dumps")
	snapEvery := fs.String("snapshot-every", "60s", "interval between socket and process snapshots")
	raw := fs.Bool("raw", false, "also keep a rotated raw journal of events and dump markers")
	memLimit := fs.String("go-memory-limit", "", "soft Go runtime memory limit (e.g. 512MiB); not a cap on RSS")
	maxActive := fs.Int("max-active", 200000, "maximum active flows")
	maxKnown := fs.Int("max-known", 100000, "maximum known dependencies")
	maxUnknown := fs.Int("max-unknown", 50000, "maximum unknown, conflict and low confidence dependencies")
	allowNoEvents := fs.Bool("allow-no-events", false, "run even if nf_conntrack_events=0 (periodic dumps only)")
	check := fs.Bool("check", false, "run the preflight checks and exit")
	cpuProfile := fs.String("cpuprofile", "", "write a Go CPU profile to this file (for debugging)")
	memProfile := fs.String("memprofile", "", "write a Go heap profile to this file on exit (for debugging)")
	promListen := fs.String("prometheus-exporter.listen", "", "beta: serve Prometheus metrics on this address (e.g. :9917); without an explicit --duration the collector then runs until stopped and writes no checkpoint")
	promPath := fs.String("prometheus-exporter.path", "/metrics", "beta: HTTP path of the metrics")
	promTTL := fs.String("prometheus-exporter.ttl", "24h", "beta: remove a connection series idle for longer than this")
	promMax := fs.Int("prometheus-exporter.max-series", 10000, "beta: maximum label sets in the exporter table; each is two series")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	var err error
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "ipcx collect: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}
	var dur time.Duration
	if *duration != "0" {
		if dur, err = parseDuration(*duration); err != nil {
			fmt.Fprintf(stderr, "ipcx collect: --duration: %v\n", err)
			return exitUsage
		}
	}
	explicit := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
	// Exporter only: no checkpoint, so nothing but the lock file is written.
	noCheckpoint := *promListen != "" && !explicit["duration"]
	if noCheckpoint {
		dur = 0
		if *raw {
			fmt.Fprintln(stderr, "ipcx collect: --raw writes to disk; with --prometheus-exporter.listen it needs an explicit --duration")
			return exitUsage
		}
	}
	promTTLv, err := parseDuration(*promTTL)
	if err != nil {
		fmt.Fprintf(stderr, "ipcx collect: --prometheus-exporter.ttl: %v\n", err)
		return exitUsage
	}
	if *promMax <= 0 {
		fmt.Fprintln(stderr, "ipcx collect: --prometheus-exporter.max-series must be positive")
		return exitUsage
	}
	if !strings.HasPrefix(*promPath, "/") {
		fmt.Fprintln(stderr, "ipcx collect: --prometheus-exporter.path must start with /")
		return exitUsage
	}
	ck, err := parseDuration(*ckEvery)
	if err != nil {
		fmt.Fprintf(stderr, "ipcx collect: --checkpoint: %v\n", err)
		return exitUsage
	}
	dumpIv, err := parseDuration(*dumpEvery)
	if err != nil {
		fmt.Fprintf(stderr, "ipcx collect: --dump-every: %v\n", err)
		return exitUsage
	}
	snapIv, err := parseDuration(*snapEvery)
	if err != nil {
		fmt.Fprintf(stderr, "ipcx collect: --snapshot-every: %v\n", err)
		return exitUsage
	}
	if *memLimit != "" {
		n, err := parseSize(*memLimit)
		if err != nil {
			fmt.Fprintf(stderr, "ipcx collect: --go-memory-limit: %v\n", err)
			return exitUsage
		}
		debug.SetMemoryLimit(n)
	}

	if *cpuProfile != "" {
		stop, err := startCPUProfile(*cpuProfile)
		if err != nil {
			fmt.Fprintf(stderr, "ipcx collect: --cpuprofile: %v\n", err)
			return exitUsage
		}
		defer stop()
	}
	if *memProfile != "" {
		defer writeHeapProfile(*memProfile, stderr)
	}

	cfg := collector.Config{
		Duration:        dur,
		CheckpointEvery: ck,
		DumpEvery:       dumpIv,
		SockEvery:       snapIv,
		ProcEvery:       snapIv,
		ShutdownTimeout: 30 * time.Second,
		StateDir:        *stateDir,
		Backoff:         []time.Duration{time.Second, 2 * time.Second, 5 * time.Second, 10 * time.Second, 30 * time.Second},
		Limits: flows.Limits{MaxActive: *maxActive, MaxKnown: *maxKnown, MaxUnknown: *maxUnknown,
			MaxProcesses: 5, MaxExamples: 3},
		AllowNoEvents: *allowNoEvents,
		NoCheckpoint:  noCheckpoint,
		Version:       version,
		Commit:        commit,
		Params:        map[string]string{},
	}
	fs.Visit(func(f *flag.Flag) { cfg.Params[f.Name] = f.Value.String() })
	if *raw {
		cfg.OpenRaw = func(runID string) (collector.RawSink, error) {
			return rawlog.Open(*stateDir, runID, 32<<20, 256<<20)
		}
	}
	src := collector.LinuxSources("/proc", "/etc")

	if *check {
		results, ok := collector.Preflight(cfg, src)
		for _, r := range results {
			status := "ok"
			switch {
			case !r.OK && r.Fatal:
				status = "fail"
			case !r.OK:
				status = "warn"
			}
			fmt.Fprintf(stdout, "%-4s  %-16s %s\n", status, r.Name, r.Detail)
		}
		if !ok {
			return exitPreflight
		}
		return exitOK
	}

	if err := os.MkdirAll(*stateDir, 0o700); err != nil {
		fmt.Fprintf(stderr, "ipcx collect: %v\n", err)
		return exitPreflight
	}
	log := slog.New(slog.NewJSONHandler(stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *promListen == "" {
		return collector.Run(ctx, cfg, src, log)
	}

	table := exporter.New(promTTLv, *promMax, exporter.BuildInfo{Version: version, Commit: commit})
	cfg.Exporter = table
	ms, err := startMetricsServer(*promListen, *promPath, table.Handler())
	if err != nil {
		fmt.Fprintf(stderr, "ipcx collect: --prometheus-exporter.listen: %v\n", err)
		return exitPreflight
	}
	until := "stopped"
	if dur > 0 {
		until = dur.String()
	}
	log.Info("prometheus exporter (beta)", "listen", ms.addr.String(), "path", *promPath,
		"checkpoints", !noCheckpoint, "runs_until", until)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	served := make(chan bool, 1)
	go func() {
		select {
		case err := <-ms.failed:
			log.Error("prometheus exporter stopped serving", "err", err)
			served <- false
			cancel()
		case <-runCtx.Done():
			served <- true
		}
	}()
	code := collector.Run(runCtx, cfg, src, log)
	cancel()
	ms.close()
	if !<-served && code == exitOK {
		code = exitRuntime
	}
	return code
}

func parseSize(s string) (int64, error) {
	units := []struct {
		suffix string
		mult   int64
	}{{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}}
	mult := int64(1)
	num := s
	for _, u := range units {
		if strings.HasSuffix(s, u.suffix) {
			mult, num = u.mult, strings.TrimSuffix(s, u.suffix)
			break
		}
	}
	n, err := strconv.ParseInt(num, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid size %q (use bytes or KiB, MiB, GiB)", s)
	}
	return n * mult, nil
}
