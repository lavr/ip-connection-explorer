package collector

import (
	"context"
	"io"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lavr/ip-connection-explorer/internal/conntrack"
	"github.com/lavr/ip-connection-explorer/internal/exporter"
	"github.com/lavr/ip-connection-explorer/internal/flows"
	"github.com/lavr/ip-connection-explorer/internal/model"
	"github.com/lavr/ip-connection-explorer/internal/procindex"
)

// TestPipelineSustainsRate drives the collector with an open-loop generator: events are
// offered on a clock and dropped when the queue is full, so a slow consumer shows up as
// drops instead of silently slowing the generator. Run with IPCX_LOAD=1.
func TestPipelineSustainsRate(t *testing.T) {
	if os.Getenv("IPCX_LOAD") == "" {
		t.Skip("set IPCX_LOAD=1 to run the load test")
	}
	t.Run("checkpoint", func(t *testing.T) { sustainRate(t, false) })
	t.Run("exporter", func(t *testing.T) { sustainRate(t, true) })
}

// sustainRate with an exporter also ends some flows and scrapes the table while it runs.
func sustainRate(t *testing.T, withExporter bool) {
	const (
		flowsN   = 50000
		socketsN = 10000
		rate     = 10000
		duration = 10 * time.Second
	)
	vip := model.Endpoint{Addr: netip.MustParseAddr("192.0.2.10"), Port: 443}
	remote := func(i int) model.Endpoint {
		return model.Endpoint{Addr: netip.AddrFrom4([4]byte{198, 51, byte(100 + i/50000), byte(i / 250 % 200)}), Port: uint16(1024 + i%60000)}
	}
	flowAt := func(i int) flows.CTFlow {
		o := model.Tuple{Src: remote(i), Dst: vip, Proto: model.ProtoTCP}
		return flows.CTFlow{ID: uint32(i + 1), Orig: o, Reply: model.Tuple{Src: o.Dst, Dst: o.Src, Proto: model.ProtoTCP}}
	}
	var socks []flows.Socket
	byInode := map[uint32][]flows.Proc{}
	socks = append(socks, flows.Socket{Proto: model.ProtoTCP, Local: model.Endpoint{Addr: netip.IPv4Unspecified(), Port: 443}, State: model.SockListen})
	for i := 0; i < socketsN; i++ {
		socks = append(socks, flows.Socket{Proto: model.ProtoTCP, Local: vip, Remote: remote(i), State: model.SockEstablished, Inode: uint32(i + 1)})
		byInode[uint32(i+1)] = []flows.Proc{{PID: 1, Comm: "nginx"}}
	}
	baseline := make([]flows.CTFlow, flowsN)
	for i := range baseline {
		baseline[i] = flowAt(i)
	}

	var offered, dropped atomic.Int64
	env := &fakeEnv{eventsValue: 1}
	src := env.sources()
	src.Dump = func(ctx context.Context, attempt, epoch uint64, b bool) (flows.DumpResult, conntrack.DumpStats, error) {
		now := time.Now()
		return flows.DumpResult{Attempt: attempt, Epoch: epoch, Started: now, Finished: now, Flows: baseline, Complete: true, Baseline: b}, conntrack.DumpStats{}, nil
	}
	src.Sockets = func(now time.Time) (flows.SockSnapshot, error) {
		return flows.SockSnapshot{At: now, Sockets: socks, Complete: true}, nil
	}
	src.Procs = func(now time.Time) (flows.ProcIndex, procindex.Stats, error) {
		return flows.ProcIndex{At: now, ByInode: byInode}, procindex.Stats{}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env.subscribe = func(epoch uint64) (Subscription, error) {
		s := newFakeSub(4096)
		if epoch != 1 {
			return s, nil
		}
		go func() {
			tick := time.NewTicker(time.Millisecond)
			defer tick.Stop()
			start := time.Now()
			sent := 0
			for now := range tick.C {
				if ctx.Err() != nil || now.Sub(start) > duration {
					return
				}
				due := int(now.Sub(start).Seconds() * rate)
				for ; sent < due; sent++ {
					kind := flows.EventUpdate
					if sent%10 == 0 {
						kind = flows.EventNew
					} else if withExporter && sent%10 == 5 {
						kind = flows.EventDestroy
					}
					ev := flows.CTEvent{Kind: kind, At: now, Epoch: 1, Flow: flowAt((sent * 7919) % flowsN)}
					offered.Add(1)
					select {
					case s.events <- ev:
					default:
						dropped.Add(1)
					}
				}
			}
		}()
		return s, nil
	}
	cfg := testConfig(t.TempDir())
	cfg.Duration = duration + 2*time.Second
	cfg.CheckpointEvery, cfg.DumpEvery, cfg.SockEvery, cfg.ProcEvery = time.Second, 3*time.Second, time.Second, time.Second
	cfg.Limits = flows.Limits{MaxActive: 200000, MaxKnown: 100000, MaxUnknown: 50000, MaxProcesses: 5, MaxExamples: 3}
	var table *exporter.Table
	if withExporter {
		table = exporter.New(time.Hour, 10000, exporter.BuildInfo{})
		cfg.Exporter = table
		go func() {
			for ctx.Err() == nil {
				_ = table.WriteText(io.Discard)
				time.Sleep(100 * time.Millisecond)
			}
		}()
	}
	done := runAsync(ctx, cfg, src)
	var code int
	select {
	case code = <-done:
	case <-time.After(cfg.Duration + 30*time.Second):
		t.Fatal("Run did not return")
	}
	cancel()
	if code != ExitOK {
		t.Fatalf("code=%d", code)
	}
	want := int64(rate * duration / time.Second)
	if offered.Load() < want*99/100 {
		t.Fatalf("generator fell behind: offered=%d want>=%d", offered.Load(), want*99/100)
	}
	if dropped.Load() != 0 {
		t.Fatalf("dropped %d of %d offered events", dropped.Load(), offered.Load())
	}
	f := readOnly(t, cfg.StateDir)
	if f.Coverage.HistoryIncomplete || len(f.Coverage.Gaps) != 0 {
		t.Fatalf("coverage: %+v", f.Coverage)
	}
	t.Logf("offered=%d dropped=%d deps=%d", offered.Load(), dropped.Load(), len(f.Dependencies))
	if withExporter {
		var b strings.Builder
		_ = table.WriteText(&b)
		if !strings.Contains(b.String(), "ipcx_exporter_ready 1") || !strings.Contains(b.String(), "ipcx_connections_finished_total{") {
			t.Fatalf("exporter output:\n%.2000s", b.String())
		}
	}
}
