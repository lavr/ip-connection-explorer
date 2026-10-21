package collector

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/lavr/ip-connection-explorer/internal/flows"
	"github.com/lavr/ip-connection-explorer/internal/model"
)

type fakeExporter struct {
	mu          sync.Mutex
	finished    []flows.Labels
	active      map[flows.Labels]int
	ready       bool
	refreshes   int
	checkpoints int
}

func (e *fakeExporter) Finished(l flows.Labels, _ time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.finished = append(e.finished, l)
}

func (e *fakeExporter) Refresh(active map[flows.Labels]int, _ flows.Health, ready bool, _ time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.active, e.ready = active, ready
	e.refreshes++
}

func (e *fakeExporter) CheckpointWritten(time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.checkpoints++
}

func (e *fakeExporter) state() (finished int, active map[flows.Labels]int, ready bool, checkpoints int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.finished), e.active, e.ready, e.checkpoints
}

func TestExporterOnlyRunWritesNoCheckpoint(t *testing.T) {
	defer goleak.VerifyNone(t)
	dir := t.TempDir()
	env := &fakeEnv{eventsValue: 1, dumpFlows: []flows.CTFlow{ctflow("192.0.2.10:40000", "198.51.100.5:443")}}
	exp := &fakeExporter{}
	cfg := testConfig(dir)
	cfg.Duration = 0
	cfg.NoCheckpoint = true
	cfg.Exporter = exp
	ctx, cancel := context.WithCancel(context.Background())
	done := runAsync(ctx, cfg, env.sources())
	want := flows.Labels{Role: model.RoleKnown, Direction: model.DirOutbound, Proto: model.ProtoTCP,
		Src: ep("192.0.2.10:0").Addr, Dst: ep("198.51.100.5:0").Addr, DstPort: 443}
	waitFor(t, func() bool { _, act, ready, _ := exp.state(); return ready && act[want] == 1 })
	time.Sleep(100 * time.Millisecond)
	cancel()
	if code := waitCode(t, done); code != ExitOK {
		t.Fatalf("code=%d", code)
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if filepath.Ext(e.Name()) == ".gz" || filepath.Ext(e.Name()) == ".tmp" {
			t.Fatalf("file written in exporter-only mode: %s", e.Name())
		}
	}
	if _, _, _, ck := exp.state(); ck != 0 {
		t.Fatalf("checkpoints=%d", ck)
	}
}

func TestExporterWithCheckpoints(t *testing.T) {
	defer goleak.VerifyNone(t)
	dir := t.TempDir()
	env := &fakeEnv{eventsValue: 1}
	env.subscribe = func(epoch uint64) (Subscription, error) {
		s := newFakeSub(4)
		if epoch == 1 {
			f := ctflow("192.0.2.10:40000", "198.51.100.5:443")
			f.TCPState, f.HasTCPState = model.CTSynSent, true
			s.events <- flows.CTEvent{Kind: flows.EventNew, At: time.Now(), Epoch: 1, Flow: f}
			s.events <- flows.CTEvent{Kind: flows.EventDestroy, At: time.Now(), Epoch: 1, Flow: f}
		}
		return s, nil
	}
	exp := &fakeExporter{}
	cfg := testConfig(dir)
	cfg.Exporter = exp
	ctx, cancel := context.WithCancel(context.Background())
	done := runAsync(ctx, cfg, env.sources())
	waitFor(t, func() bool { n, _, _, ck := exp.state(); return n == 1 && ck > 0 })
	cancel()
	if code := waitCode(t, done); code != ExitOK {
		t.Fatalf("code=%d", code)
	}
	if f := readOnly(t, dir); len(f.Dependencies) != 1 {
		t.Fatalf("%+v", f.Dependencies)
	}
}

func TestZeroDurationRunsUntilStopped(t *testing.T) {
	defer goleak.VerifyNone(t)
	dir := t.TempDir()
	env := &fakeEnv{eventsValue: 1}
	cfg := testConfig(dir)
	cfg.Duration = 0
	ctx, cancel := context.WithCancel(context.Background())
	done := runAsync(ctx, cfg, env.sources())
	select {
	case c := <-done:
		t.Fatalf("returned early with %d", c)
	case <-time.After(150 * time.Millisecond):
	}
	cancel()
	if code := waitCode(t, done); code != ExitOK {
		t.Fatalf("code=%d", code)
	}
	readOnly(t, dir)
}

func TestStaleDumpDoesNotSetReady(t *testing.T) {
	exp := &fakeExporter{}
	r := &runner{cfg: Config{Exporter: exp}, log: quiet,
		m: flows.NewMachine(flows.HostContext{MachineID: "m1"}, model.ObserverRef{}, flows.Limits{}, time.Minute, time.Minute)}
	r.epoch = 2
	r.m.SetEpoch(2)
	r.applyDump(dumpDone{res: flows.DumpResult{Attempt: 1, Epoch: 1, Complete: true}})
	if _, _, ready, _ := exp.state(); ready || r.ready {
		t.Fatal("a dump the machine rejected made the exporter ready")
	}
	r.applyDump(dumpDone{res: flows.DumpResult{Attempt: 2, Epoch: 2, Complete: true}})
	if _, _, ready, _ := exp.state(); !ready {
		t.Fatal("an accepted complete dump did not make the exporter ready")
	}
}

func TestNATView(t *testing.T) {
	for _, original := range []bool{false, true} {
		defer goleak.VerifyNone(t)
		f := ctflow("10.233.70.5:40000", "198.51.100.5:443")
		f.Reply.Dst, f.SrcNAT = ep("192.0.2.10:40000"), true
		env := &fakeEnv{eventsValue: 1, dumpFlows: []flows.CTFlow{f}}
		exp := &fakeExporter{}
		cfg := testConfig(t.TempDir())
		cfg.Exporter = exp
		cfg.OriginalNAT = original
		ctx, cancel := context.WithCancel(context.Background())
		done := runAsync(ctx, cfg, env.sources())
		want := flows.Labels{Role: model.RoleKnown, Direction: model.DirOutbound, Proto: model.ProtoTCP,
			Src: ep("192.0.2.10:0").Addr, Dst: ep("198.51.100.5:0").Addr, DstPort: 443}
		if original {
			want.Direction, want.Src = model.DirUnresolved, ep("10.233.70.5:0").Addr
		}
		waitFor(t, func() bool { _, act, ready, _ := exp.state(); return ready && act[want] == 1 })
		cancel()
		if code := waitCode(t, done); code != ExitOK {
			t.Fatalf("code=%d", code)
		}
	}
}
