package collector

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/lavr/ip-connection-explorer/internal/checkpoint"
	"github.com/lavr/ip-connection-explorer/internal/conntrack"
	"github.com/lavr/ip-connection-explorer/internal/flows"
	"github.com/lavr/ip-connection-explorer/internal/model"
	"github.com/lavr/ip-connection-explorer/internal/procindex"
)

func TestPreflightStateDirNotWritable(t *testing.T) {
	defer goleak.VerifyNone(t)
	file := filepath.Join(t.TempDir(), "not-a-dir")
	os.WriteFile(file, nil, 0o644)
	env := &fakeEnv{eventsValue: 1}
	if code := Run(context.Background(), testConfig(file), env.sources(), quiet); code != ExitPreflight {
		t.Fatalf("code=%d", code)
	}
}

func TestPreflightEventsDisabled(t *testing.T) {
	defer goleak.VerifyNone(t)
	dir := t.TempDir()
	env := &fakeEnv{eventsValue: 0}
	if code := Run(context.Background(), testConfig(dir), env.sources(), quiet); code != ExitPreflight {
		t.Fatalf("code=%d", code)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "*.json.gz")); len(m) != 0 {
		t.Fatal("checkpoint written after failed preflight")
	}
	cfg := testConfig(dir)
	cfg.AllowNoEvents = true
	ctx, cancel := context.WithCancel(context.Background())
	done := runAsync(ctx, cfg, env.sources())
	time.Sleep(50 * time.Millisecond)
	cancel()
	if code := waitCode(t, done); code != ExitOK {
		t.Fatalf("code=%d", code)
	}
	if f := readOnly(t, dir); f.Coverage.EventsSysctl != 0 {
		t.Fatalf("%+v", f.Coverage)
	}
}

func TestPreflightResults(t *testing.T) {
	env := &fakeEnv{eventsValue: 2}
	res, ok := Preflight(testConfig(t.TempDir()), env.sources())
	if !ok || len(res) < 6 {
		t.Fatalf("%v %+v", ok, res)
	}
	for _, r := range res {
		if !r.OK {
			t.Fatalf("%+v", r)
		}
	}
}

func TestLockedStateDir(t *testing.T) {
	defer goleak.VerifyNone(t)
	dir := t.TempDir()
	release, err := checkpoint.Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	env := &fakeEnv{eventsValue: 1}
	if code := Run(context.Background(), testConfig(dir), env.sources(), quiet); code != ExitLocked {
		t.Fatalf("code=%d", code)
	}
}

func TestBaselineAndEventsPersisted(t *testing.T) {
	defer goleak.VerifyNone(t)
	dir := t.TempDir()
	env := &fakeEnv{eventsValue: 1, dumpFlows: []flows.CTFlow{ctflow("198.51.100.7:51000", "192.0.2.10:5432")}}
	env.subscribe = func(epoch uint64) (Subscription, error) {
		s := newFakeSub(4)
		if epoch == 1 {
			f := ctflow("192.0.2.10:40000", "198.51.100.5:443")
			f.TCPState, f.HasTCPState = model.CTSynSent, true
			s.events <- flows.CTEvent{Kind: flows.EventNew, At: time.Now(), Epoch: 1, Flow: f}
		}
		return s, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := runAsync(ctx, testConfig(dir), env.sources())
	waitFor(t, func() bool { f := tryRead(dir); return f != nil && len(f.Dependencies) == 2 })
	cancel()
	if code := waitCode(t, done); code != ExitOK {
		t.Fatalf("code=%d", code)
	}
	f := readOnly(t, dir)
	got := map[model.Source]bool{}
	for _, d := range f.Dependencies {
		for _, s := range d.Sources {
			got[s] = true
		}
	}
	if !got[model.SourceBaseline] || !got[model.SourceEvent] || f.Run.Generation < 2 || f.Host.MachineID != "m1" || len(f.Coverage.Intervals) != 1 || f.Coverage.Intervals[0].To.IsZero() {
		t.Fatalf("%+v %+v", got, f.Run)
	}
}

func TestListenerErrorResyncs(t *testing.T) {
	defer goleak.VerifyNone(t)
	dir := t.TempDir()
	env := &fakeEnv{eventsValue: 1}
	env.subscribe = func(epoch uint64) (Subscription, error) {
		s := newFakeSub(4)
		if epoch == 1 {
			s.errc <- syscall.ENOBUFS
		}
		return s, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := runAsync(ctx, testConfig(dir), env.sources())
	waitFor(t, func() bool {
		f := tryRead(dir)
		return f != nil && len(f.Coverage.Gaps) == 1 && !f.Coverage.Gaps[0].To.IsZero()
	})
	cancel()
	if code := waitCode(t, done); code != ExitOK {
		t.Fatalf("code=%d", code)
	}
	f := readOnly(t, dir)
	g := f.Coverage.Gaps[0]
	if g.Kind != model.GapMap || g.Reason != "enobufs" || !f.Coverage.HistoryIncomplete {
		t.Fatalf("%+v", f.Coverage)
	}
	ep := env.epochList()
	if len(ep) < 3 || ep[1] != 1 || ep[2] != 2 {
		t.Fatalf("epochs=%v", ep)
	}
}

func TestRetriesExhaustedWritesPartialAndExits1(t *testing.T) {
	defer goleak.VerifyNone(t)
	dir := t.TempDir()
	env := &fakeEnv{eventsValue: 1}
	env.subscribe = func(epoch uint64) (Subscription, error) {
		switch epoch {
		case 0:
			return newFakeSub(1), nil
		case 1:
			s := newFakeSub(1)
			s.errc <- errors.New("listener died")
			return s, nil
		}
		return nil, errors.New("cannot subscribe")
	}
	if code := waitCode(t, runAsync(context.Background(), testConfig(dir), env.sources())); code != ExitRuntime {
		t.Fatalf("code=%d", code)
	}
	f := readOnly(t, dir)
	if len(f.Coverage.Gaps) != 1 || f.Coverage.Gaps[0].To.IsZero() || !f.Coverage.HistoryIncomplete {
		t.Fatalf("%+v", f.Coverage)
	}
}

func TestFinalCheckpointFailureExits1(t *testing.T) {
	defer goleak.VerifyNone(t)
	dir := t.TempDir()
	env := &fakeEnv{eventsValue: 1}
	var failing atomic.Bool
	cfg := testConfig(dir)
	cfg.Write = func(d string, f *checkpoint.File) (string, error) {
		if failing.Load() {
			return "", errors.New("disk full")
		}
		return checkpoint.Write(d, f)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := runAsync(ctx, cfg, env.sources())
	waitFor(t, func() bool { return tryRead(dir) != nil })
	failing.Store(true)
	cancel()
	if code := waitCode(t, done); code != ExitRuntime {
		t.Fatalf("code=%d", code)
	}
	if f := tryRead(dir); f == nil {
		t.Fatal("previous checkpoint lost")
	}
}

func TestNoCheckpointEverIsFailure(t *testing.T) {
	defer goleak.VerifyNone(t)
	dir := t.TempDir()
	env := &fakeEnv{eventsValue: 1}
	cfg := testConfig(dir)
	cfg.Write = func(string, *checkpoint.File) (string, error) { return "", errors.New("disk full") }
	ctx, cancel := context.WithCancel(context.Background())
	done := runAsync(ctx, cfg, env.sources())
	time.Sleep(60 * time.Millisecond)
	cancel()
	if code := waitCode(t, done); code != ExitRuntime {
		t.Fatalf("code=%d", code)
	}
}

func TestShutdownDrainsEvents(t *testing.T) {
	defer goleak.VerifyNone(t)
	dir := t.TempDir()
	env := &fakeEnv{eventsValue: 1}
	started := make(chan struct{})
	env.subscribe = func(epoch uint64) (Subscription, error) {
		s := newFakeSub(100)
		if epoch == 1 {
			for i := 0; i < 100; i++ {
				f := ctflow("192.0.2.10:40000", "198.51.100.5:443")
				f.Orig.Src.Port += uint16(i)
				f.Reply.Dst.Port += uint16(i)
				s.events <- flows.CTEvent{Kind: flows.EventNew, At: time.Now(), Epoch: 1, Flow: f}
			}
			close(started)
		}
		return s, nil
	}
	cfg := testConfig(dir)
	cfg.CheckpointEvery = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	done := runAsync(ctx, cfg, env.sources())
	<-started
	cancel()
	if code := waitCode(t, done); code != ExitOK {
		t.Fatalf("code=%d", code)
	}
	f := readOnly(t, dir)
	if len(f.Dependencies) != 1 || f.Dependencies[0].FlowsObserved != 100 {
		t.Fatalf("%+v", f.Dependencies)
	}
}

func TestAttributionFailureContinues(t *testing.T) {
	defer goleak.VerifyNone(t)
	dir := t.TempDir()
	env := &fakeEnv{eventsValue: 1, procsErr: errors.New("permission denied")}
	ctx, cancel := context.WithCancel(context.Background())
	done := runAsync(ctx, testConfig(dir), env.sources())
	waitFor(t, func() bool { return tryRead(dir) != nil })
	cancel()
	if code := waitCode(t, done); code != ExitOK {
		t.Fatalf("code=%d", code)
	}
	f := readOnly(t, dir)
	if f.Coverage.HistoryIncomplete || len(f.Coverage.Gaps) != 1 || f.Coverage.Gaps[0].Kind != model.GapAttribution {
		t.Fatalf("%+v", f.Coverage)
	}
}

func TestDurationEndsRun(t *testing.T) {
	defer goleak.VerifyNone(t)
	dir := t.TempDir()
	env := &fakeEnv{eventsValue: 1}
	cfg := testConfig(dir)
	cfg.Duration = 80 * time.Millisecond
	if code := waitCode(t, runAsync(context.Background(), cfg, env.sources())); code != ExitOK {
		t.Fatalf("code=%d", code)
	}
	readOnly(t, dir)
}

func TestPreflightCreatesMissingStateDirLater(t *testing.T) {
	env := &fakeEnv{eventsValue: 1}
	res, ok := Preflight(testConfig(filepath.Join(t.TempDir(), "not-yet")), env.sources())
	if !ok || !res[0].OK {
		t.Fatalf("%+v", res[0])
	}
}

func TestResyncDoesNotBlockEvents(t *testing.T) {
	defer goleak.VerifyNone(t)
	dir := t.TempDir()
	env := &fakeEnv{eventsValue: 1}
	release := make(chan struct{})
	src := env.sources()
	inner := src.Dump
	src.Dump = func(ctx context.Context, attempt, epoch uint64, baseline bool) (flows.DumpResult, conntrack.DumpStats, error) {
		if epoch == 1 && baseline {
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
		return inner(ctx, attempt, epoch, baseline)
	}
	env.subscribe = func(epoch uint64) (Subscription, error) {
		s := newFakeSub(4)
		if epoch == 1 {
			f := ctflow("192.0.2.10:40000", "198.51.100.5:443")
			s.events <- flows.CTEvent{Kind: flows.EventNew, At: time.Now(), Epoch: 1, Flow: f}
		}
		return s, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := runAsync(ctx, testConfig(dir), src)
	waitFor(t, func() bool { f := tryRead(dir); return f != nil && len(f.Dependencies) == 1 })
	close(release)
	cancel()
	if code := waitCode(t, done); code != ExitOK {
		t.Fatalf("code=%d", code)
	}
}

func TestHungSnapshotStillWritesFinalCheckpoint(t *testing.T) {
	dir := t.TempDir()
	env := &fakeEnv{eventsValue: 1}
	src := env.sources()
	hang := make(chan struct{})
	var calls atomic.Int32
	inner := src.Sockets
	src.Sockets = func(now time.Time) (flows.SockSnapshot, error) {
		if calls.Add(1) > 2 {
			<-hang
		}
		return inner(now)
	}
	cfg := testConfig(dir)
	cfg.CheckpointEvery = time.Hour
	cfg.ShutdownTimeout = 200 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := runAsync(ctx, cfg, src)
	waitFor(t, func() bool { return calls.Load() > 2 })
	cancel()
	code := waitCode(t, done)
	close(hang)
	if code != ExitRuntime {
		t.Fatalf("code=%d", code)
	}
	f := readOnly(t, dir)
	found := false
	for _, g := range f.Coverage.Gaps {
		if g.Kind == model.GapAttribution && g.Reason == "sock_stuck" {
			found = true
		}
	}
	if !found {
		t.Fatalf("%+v", f.Coverage.Gaps)
	}
}

func TestStuckJobOpensGapDuringRun(t *testing.T) {
	dir := t.TempDir()
	env := &fakeEnv{eventsValue: 1}
	src := env.sources()
	hang := make(chan struct{})
	defer close(hang)
	var calls atomic.Int32
	inner := src.Procs
	src.Procs = func(now time.Time) (flows.ProcIndex, procindex.Stats, error) {
		if calls.Add(1) > 2 {
			<-hang
		}
		return inner(now)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := testConfig(dir)
	cfg.ShutdownTimeout = 100 * time.Millisecond
	done := runAsync(ctx, cfg, src)
	waitFor(t, func() bool {
		f := tryRead(dir)
		if f == nil {
			return false
		}
		for _, g := range f.Coverage.Gaps {
			if g.Kind == model.GapAttribution && g.Reason == "proc_stuck" {
				return true
			}
		}
		return false
	})
	cancel()
	waitCode(t, done)
}

func TestOldWriterCannotOverwriteFinal(t *testing.T) {
	dir := t.TempDir()
	env := &fakeEnv{eventsValue: 1}
	block := make(chan struct{})
	started := make(chan struct{})
	var once atomic.Bool
	oldDone := make(chan struct{})
	cfg := testConfig(dir)
	cfg.ShutdownTimeout = 30 * time.Millisecond
	cfg.Write = func(d string, f *checkpoint.File) (string, error) {
		if f.Run.Generation == 1 && once.CompareAndSwap(false, true) {
			close(started)
			<-block
			defer close(oldDone)
		}
		return checkpoint.Write(d, f)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := runAsync(ctx, cfg, env.sources())
	<-started
	cancel()
	waitCode(t, done)
	close(block)
	<-oldDone
	if f := readOnly(t, dir); f.Run.Generation < 2 {
		t.Fatalf("final checkpoint replaced by generation %d", f.Run.Generation)
	}
}
