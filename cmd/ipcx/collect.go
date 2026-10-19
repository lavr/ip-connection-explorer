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
	"github.com/lavr/ip-connection-explorer/internal/flows"
	"github.com/lavr/ip-connection-explorer/internal/rawlog"
)

func runCollect(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("collect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	duration := fs.String("duration", "7d", "how long to collect (e.g. 7d, 36h)")
	stateDir := fs.String("state-dir", "/var/lib/ipcx", "directory for checkpoints and the lock file")
	ckEvery := fs.String("checkpoint", "2m", "checkpoint interval")
	raw := fs.Bool("raw", false, "also keep a rotated raw journal of events and dump markers")
	memLimit := fs.String("go-memory-limit", "", "soft Go runtime memory limit (e.g. 512MiB); not a cap on RSS")
	maxActive := fs.Int("max-active", 200000, "maximum active flows")
	maxKnown := fs.Int("max-known", 100000, "maximum known dependencies")
	maxUnknown := fs.Int("max-unknown", 50000, "maximum unknown, conflict and low confidence dependencies")
	allowNoEvents := fs.Bool("allow-no-events", false, "run even if nf_conntrack_events=0 (periodic dumps only)")
	check := fs.Bool("check", false, "run the preflight checks and exit")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "ipcx collect: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}
	dur, err := parseDuration(*duration)
	if err != nil {
		fmt.Fprintf(stderr, "ipcx collect: --duration: %v\n", err)
		return exitUsage
	}
	ck, err := parseDuration(*ckEvery)
	if err != nil {
		fmt.Fprintf(stderr, "ipcx collect: --checkpoint: %v\n", err)
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

	cfg := collector.Config{
		Duration:        dur,
		CheckpointEvery: ck,
		DumpEvery:       5 * time.Minute,
		SockEvery:       time.Minute,
		ProcEvery:       time.Minute,
		ShutdownTimeout: 30 * time.Second,
		StateDir:        *stateDir,
		Backoff:         []time.Duration{time.Second, 2 * time.Second, 5 * time.Second, 10 * time.Second, 30 * time.Second},
		Limits: flows.Limits{MaxActive: *maxActive, MaxKnown: *maxKnown, MaxUnknown: *maxUnknown,
			MaxProcesses: 5, MaxExamples: 3},
		AllowNoEvents: *allowNoEvents,
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return collector.Run(ctx, cfg, src, slog.New(slog.NewJSONHandler(stderr, nil)))
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
