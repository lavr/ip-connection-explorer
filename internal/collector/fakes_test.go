package collector

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lavr/ip-connection-explorer/internal/checkpoint"
	"github.com/lavr/ip-connection-explorer/internal/conntrack"
	"github.com/lavr/ip-connection-explorer/internal/flows"
	"github.com/lavr/ip-connection-explorer/internal/hostinfo"
	"github.com/lavr/ip-connection-explorer/internal/model"
	"github.com/lavr/ip-connection-explorer/internal/procindex"
)

type fakeSub struct {
	events    chan flows.CTEvent
	errc      chan error
	closeOnce sync.Once
}

func newFakeSub(n int) *fakeSub {
	return &fakeSub{events: make(chan flows.CTEvent, n), errc: make(chan error, 1)}
}

func (s *fakeSub) Events() <-chan flows.CTEvent { return s.events }
func (s *fakeSub) Err() <-chan error            { return s.errc }
func (s *fakeSub) Close(context.Context) error {
	s.closeOnce.Do(func() { close(s.events) })
	return nil
}

type fakeEnv struct {
	mu          sync.Mutex
	epochs      []uint64
	subscribe   func(epoch uint64) (Subscription, error)
	dumpFlows   []flows.CTFlow
	eventsValue int
	procsErr    error
}

func ep(s string) model.Endpoint {
	ap := netip.MustParseAddrPort(s)
	return model.Endpoint{Addr: ap.Addr(), Port: ap.Port()}
}

func ctflow(src, dst string) flows.CTFlow {
	o := model.Tuple{Src: ep(src), Dst: ep(dst), Proto: model.ProtoTCP}
	return flows.CTFlow{Orig: o, Reply: model.Tuple{Src: o.Dst, Dst: o.Src, Proto: model.ProtoTCP}}
}

func (e *fakeEnv) sources() Sources {
	return Sources{
		Subscribe: func(epoch uint64) (Subscription, error) {
			e.mu.Lock()
			e.epochs = append(e.epochs, epoch)
			fn := e.subscribe
			e.mu.Unlock()
			if fn != nil {
				return fn(epoch)
			}
			return newFakeSub(16), nil
		},
		Dump: func(ctx context.Context, attempt, epoch uint64, baseline bool) (flows.DumpResult, conntrack.DumpStats, error) {
			now := time.Now()
			return flows.DumpResult{Attempt: attempt, Epoch: epoch, Started: now, Finished: now, Flows: e.dumpFlows, Complete: true, Baseline: baseline}, conntrack.DumpStats{}, nil
		},
		Sockets: func(now time.Time) (flows.SockSnapshot, error) {
			return flows.SockSnapshot{At: now, Complete: true}, nil
		},
		Procs: func(now time.Time) (flows.ProcIndex, procindex.Stats, error) {
			return flows.ProcIndex{At: now, ByInode: map[uint32][]flows.Proc{}}, procindex.Stats{}, e.procsErr
		},
		Host: func() (hostinfo.Info, error) {
			return hostinfo.Info{Hostname: "h1", MachineID: "m1", BootID: "b1", Kernel: "6.8", PortRangeLow: 32768, PortRangeHigh: 60999}, nil
		},
		Addresses: func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil },
		EventsSysctl: func() (int, error) {
			return e.eventsValue, nil
		},
	}
}

func (e *fakeEnv) epochList() []uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]uint64(nil), e.epochs...)
}

func testConfig(dir string) Config {
	return Config{
		Duration:        time.Hour,
		CheckpointEvery: 20 * time.Millisecond,
		DumpEvery:       30 * time.Millisecond,
		SockEvery:       30 * time.Millisecond,
		ProcEvery:       30 * time.Millisecond,
		ShutdownTimeout: 2 * time.Second,
		StateDir:        dir,
		Backoff:         []time.Duration{time.Millisecond, time.Millisecond},
		Limits:          flows.Limits{MaxActive: 1000, MaxKnown: 1000, MaxUnknown: 1000, MaxProcesses: 5, MaxExamples: 3},
		Version:         "test",
	}
}

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func runAsync(ctx context.Context, cfg Config, src Sources) <-chan int {
	done := make(chan int, 1)
	go func() { done <- Run(ctx, cfg, src, quiet) }()
	return done
}

func waitCode(t *testing.T, done <-chan int) int {
	t.Helper()
	select {
	case c := <-done:
		return c
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
		return -1
	}
}

func readOnly(t *testing.T, dir string) *checkpoint.File {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(dir, "*.json.gz"))
	if len(m) != 1 {
		t.Fatalf("want 1 checkpoint, got %v", m)
	}
	f, err := checkpoint.Read(m[0])
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}

func tryRead(dir string) *checkpoint.File {
	m, _ := filepath.Glob(filepath.Join(dir, "*.json.gz"))
	if len(m) != 1 {
		return nil
	}
	f, err := checkpoint.Read(m[0])
	if err != nil {
		return nil
	}
	return f
}

