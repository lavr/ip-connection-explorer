package collector

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"syscall"
	"time"

	"github.com/lavr/ip-connection-explorer/internal/checkpoint"
	"github.com/lavr/ip-connection-explorer/internal/conntrack"
	"github.com/lavr/ip-connection-explorer/internal/flows"
	"github.com/lavr/ip-connection-explorer/internal/hostinfo"
	"github.com/lavr/ip-connection-explorer/internal/model"
	"github.com/lavr/ip-connection-explorer/internal/procindex"
)

const (
	ExitOK        = 0
	ExitRuntime   = 1
	ExitUsage     = 2
	ExitPreflight = 3
	ExitLocked    = 4
)

type Subscription interface {
	Events() <-chan flows.CTEvent
	Err() <-chan error
	Close(ctx context.Context) error
}

type Sources struct {
	// Kernel checks conntrack availability without touching netlink and returns the number
	// of tracked entries. Nil means no check.
	Kernel       func() (int, error)
	Subscribe    func(epoch uint64) (Subscription, error)
	Dump         func(ctx context.Context, attempt, epoch uint64, baseline bool) (flows.DumpResult, conntrack.DumpStats, error)
	Sockets      func(now time.Time) (flows.SockSnapshot, error)
	Procs        func(now time.Time) (flows.ProcIndex, procindex.Stats, error)
	Host         func() (hostinfo.Info, error)
	Addresses    func() ([]netip.Addr, error)
	EventsSysctl func() (int, error)
}

type RawSink interface {
	Write(rec any) error
	Close() error
}

// Exporter receives every finished connection and periodic samples of the active ones.
type Exporter interface {
	Finished(l flows.Labels, at time.Time)
	Refresh(active map[flows.Labels]int, h flows.Health, ready bool, now time.Time)
	CheckpointWritten(at time.Time)
}

type Config struct {
	// Duration 0 runs until stopped.
	Duration        time.Duration
	CheckpointEvery time.Duration
	DumpEvery       time.Duration
	SockEvery       time.Duration
	ProcEvery       time.Duration
	ShutdownTimeout time.Duration
	StateDir        string
	Backoff         []time.Duration
	Limits          flows.Limits
	AllowNoEvents   bool
	OpenRaw         func(runID string) (RawSink, error)
	Version, Commit string
	Params          map[string]string
	Write           func(dir string, f *checkpoint.File) (string, error)
	Exporter        Exporter
	// NoCheckpoint writes no checkpoint and keeps no report state; only the lock file is
	// created in StateDir.
	NoCheckpoint bool
	// OriginalNAT records masqueraded connections from their original source, not from the
	// host address they leave from.
	OriginalNAT bool
}

func (c *Config) defaults() {
	if c.Write == nil {
		c.Write = checkpoint.Write
	}
	if c.ShutdownTimeout == 0 {
		c.ShutdownTimeout = 30 * time.Second
	}
}

type dumpDone struct {
	res flows.DumpResult
	st  conntrack.DumpStats
	err error
}

type sockDone struct {
	snap  flows.SockSnapshot
	addrs []netip.Addr
	err   error
}

type procDone struct {
	idx flows.ProcIndex
	st  procindex.Stats
	err error
}

type runner struct {
	cfg  Config
	raw  RawSink
	src  Sources
	log  *slog.Logger
	m    *flows.Machine
	info hostinfo.Info

	runID   string
	started time.Time
	gen     uint64
	lastOK  *time.Time
	written bool

	epoch    uint64
	attempt  uint64
	sub      Subscription
	failures int
	retry    <-chan time.Time
	fatal    bool

	sockFailing, procFailing bool

	dumpC chan dumpDone
	sockC chan sockDone
	procC chan procDone
	ckC   chan error
	busy  map[string]bool
	since map[string]time.Time
	stuck map[string]bool

	baselineDone bool
	wantResync   bool
	ready        bool
}

func now() time.Time { return time.Now().UTC() }

func Run(ctx context.Context, cfg Config, src Sources, log *slog.Logger) int {
	cfg.defaults()
	release, err := checkpoint.Lock(cfg.StateDir)
	if errors.Is(err, checkpoint.ErrLocked) {
		log.Error("state directory locked by another collector", "dir", cfg.StateDir)
		return ExitLocked
	}
	if err != nil {
		log.Error("cannot lock state directory", "dir", cfg.StateDir, "err", err)
		return ExitPreflight
	}
	defer release()

	results, ok := Preflight(cfg, src)
	for _, r := range results {
		log.Info("preflight", "check", r.Name, "ok", r.OK, "fatal", r.Fatal, "detail", r.Detail)
	}
	if !ok {
		return ExitPreflight
	}
	info, err := src.Host()
	if err != nil {
		log.Error("host info", "err", err)
		return ExitPreflight
	}
	runID := checkpoint.NewRunID()
	var raw RawSink
	if cfg.OpenRaw != nil {
		if raw, err = cfg.OpenRaw(runID); err != nil {
			log.Warn("raw journal disabled", "err", err)
		}
	}
	r := &runner{
		cfg: cfg, src: src, log: log, info: info, raw: raw,
		runID:   runID,
		started: now(),
		dumpC:   make(chan dumpDone, 1),
		sockC:   make(chan sockDone, 1),
		procC:   make(chan procDone, 1),
		ckC:     make(chan error, 1),
		busy:    map[string]bool{},
		since:   map[string]time.Time{},
		stuck:   map[string]bool{},
	}
	return r.run(ctx)
}

func (r *runner) run(ctx context.Context) int {
	h := flows.HostContext{MachineID: r.info.MachineID, Hostname: r.info.Hostname,
		PortRangeLow: r.info.PortRangeLow, PortRangeHigh: r.info.PortRangeHigh}
	obs := model.ObserverRef{Hostname: r.info.Hostname, MachineID: r.info.MachineID, RunID: r.runID}
	r.m = flows.NewMachine(h, obs, r.cfg.Limits, 2*r.cfg.SockEvery, 2*r.cfg.DumpEvery)
	if v, err := r.src.EventsSysctl(); err == nil {
		r.m.SetEventsSysctl(v)
	} else {
		r.m.SetEventsSysctl(-1)
	}
	r.m.StartInterval(r.started)
	if r.cfg.NoCheckpoint {
		r.m.DisableReport()
	}
	if r.cfg.OriginalNAT {
		r.m.KeepOriginalNAT()
	}
	if r.cfg.Exporter != nil {
		r.m.OnFinish(r.cfg.Exporter.Finished)
	}

	now := now()
	r.applySockets(r.collectSockets(now))
	r.applyProcs(r.collectProcs(now))

	r.epoch = 1
	r.m.SetEpoch(r.epoch)
	if sub, err := r.src.Subscribe(r.epoch); err != nil {
		r.listenerFailed(err)
	} else {
		r.sub = sub
		r.resync(ctx)
	}

	tick := func(d time.Duration) *time.Ticker {
		if d <= 0 {
			d = time.Hour
		}
		return time.NewTicker(d)
	}
	dumpT, sockT, procT := tick(r.cfg.DumpEvery), tick(r.cfg.SockEvery), tick(r.cfg.ProcEvery)
	defer dumpT.Stop()
	defer sockT.Stop()
	defer procT.Stop()
	// A nil channel never fires: no checkpoints, no deadline or no exporter refresh.
	var ckC, deadlineC, expC <-chan time.Time
	if !r.cfg.NoCheckpoint {
		ckT := tick(r.cfg.CheckpointEvery)
		defer ckT.Stop()
		ckC = ckT.C
	}
	if r.cfg.Duration > 0 {
		deadline := time.NewTimer(r.cfg.Duration)
		defer deadline.Stop()
		deadlineC = deadline.C
	}
	if r.cfg.Exporter != nil {
		expT := tick(r.cfg.SockEvery)
		defer expT.Stop()
		expC = expT.C
	}

	for !r.fatal {
		var events <-chan flows.CTEvent
		var errc <-chan error
		if r.sub != nil {
			events, errc = r.sub.Events(), r.sub.Err()
		}
		select {
		case <-ctx.Done():
			return r.shutdown()
		case <-deadlineC:
			return r.shutdown()
		case ev, ok := <-events:
			if !ok {
				r.listenerFailed(errors.New("event channel closed"))
				continue
			}
			r.applyEvent(ev)
		case err := <-errc:
			r.listenerFailed(err)
		case <-r.retry:
			r.retry = nil
			r.resubscribe(ctx)
		case <-dumpT.C:
			r.checkStuck("dump", r.cfg.DumpEvery)
			r.startDump(ctx)
		case d := <-r.dumpC:
			r.done("dump")
			r.applyDump(d)
			if r.wantResync {
				r.startDump(ctx)
			}
		case <-sockT.C:
			r.checkStuck("sock", r.cfg.SockEvery)
			r.startSockets()
		case s := <-r.sockC:
			r.done("sock")
			r.applySockets(s)
		case <-procT.C:
			r.checkStuck("proc", r.cfg.ProcEvery)
			r.startProcs()
		case p := <-r.procC:
			r.done("proc")
			r.applyProcs(p)
		case <-expC:
			r.refreshExporter()
		case <-ckC:
			r.checkStuck("ck", r.cfg.CheckpointEvery)
			r.startCheckpoint()
		case err := <-r.ckC:
			r.done("ck")
			r.checkpointDone(err)
		}
	}
	return r.shutdown()
}

func (r *runner) applyEvent(ev flows.CTEvent) {
	r.m.ApplyEvent(ev)
	if r.raw != nil {
		r.rawWrite(map[string]any{"at": ev.At, "run_id": r.runID, "epoch": ev.Epoch, "source": "event", "kind": ev.Kind, "flow": ev.Flow})
	}
}

func (r *runner) rawWrite(rec any) {
	if err := r.raw.Write(rec); err != nil {
		r.m.Count("raw_errors", 1)
	}
}

func reason(err error) string {
	switch {
	case errors.Is(err, syscall.ENOBUFS):
		return "enobufs"
	case errors.Is(err, conntrack.ErrQueueFull):
		return "queue_full"
	}
	return "listener_error"
}

func (r *runner) listenerFailed(err error) {
	now := now()
	r.log.Warn("conntrack listener failed", "err", err)
	if !r.m.HasOpenGap(model.GapMap) {
		r.m.OpenGap(model.GapMap, reason(err), now)
	}
	r.m.Count("listener_restarts", 1)
	r.closeSub(5 * time.Second)
	r.failures++
	if r.failures > len(r.cfg.Backoff) {
		r.log.Error("conntrack listener retries exhausted", "failures", r.failures)
		r.fatal = true
		return
	}
	r.retry = time.After(r.cfg.Backoff[r.failures-1])
}

func (r *runner) closeSub(timeout time.Duration) {
	if r.sub == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := r.sub.Close(ctx); err != nil {
		r.log.Warn("conntrack listener did not close in time", "err", err)
		r.m.Count("listener_close_timeouts", 1)
	} else {
		for ev := range r.sub.Events() {
			r.applyEvent(ev)
		}
	}
	r.sub = nil
}

func (r *runner) resubscribe(ctx context.Context) {
	r.epoch++
	r.m.SetEpoch(r.epoch)
	sub, err := r.src.Subscribe(r.epoch)
	if err != nil {
		r.listenerFailed(err)
		return
	}
	r.sub = sub
	r.resync(ctx)
}

// resync asks for a full dump under the current epoch. It runs like any other dump, so the
// loop keeps reading events meanwhile; the map gap closes when a complete dump of the current
// epoch arrives.
func (r *runner) resync(ctx context.Context) {
	r.wantResync = true
	r.startDump(ctx)
}

func (r *runner) begin(kind string) {
	r.busy[kind] = true
	r.since[kind] = now()
}

func (r *runner) done(kind string) {
	r.busy[kind] = false
	r.stuck[kind] = false
}

// checkStuck opens a gap for a job that has been running for more than three intervals.
func (r *runner) checkStuck(kind string, every time.Duration) {
	if !r.busy[kind] || r.stuck[kind] || now().Sub(r.since[kind]) <= 3*every {
		return
	}
	r.markStuck(kind)
}

func (r *runner) markStuck(kind string) {
	r.stuck[kind] = true
	r.m.Count(kind+"_stuck", 1)
	r.log.Warn("job is stuck", "job", kind, "since", r.since[kind])
	switch kind {
	case "sock":
		r.setAttribution(&r.sockFailing, true, "sock_stuck")
	case "proc":
		r.setAttribution(&r.procFailing, true, "proc_stuck")
	case "dump":
		if !r.m.HasOpenGap(model.GapMap) {
			r.m.OpenGap(model.GapMap, "dump_stuck", now())
		}
	}
}

func (r *runner) startDump(ctx context.Context) {
	if r.busy["dump"] {
		r.m.Count("skipped_dump", 1)
		return
	}
	r.begin("dump")
	r.attempt++
	attempt, epoch, baseline := r.attempt, r.epoch, !r.baselineDone
	r.baselineDone = true
	r.wantResync = false
	go func() {
		res, st, err := r.src.Dump(ctx, attempt, epoch, baseline)
		r.dumpC <- dumpDone{res, st, err}
	}()
}

func (r *runner) applyDump(d dumpDone) {
	r.m.Count("dump_interrupted", uint64(d.st.Interrupted))
	r.m.Count("decode_errors", uint64(d.st.DecodeErrors))
	if d.err != nil {
		r.m.Count("dump_errors", 1)
		r.log.Warn("conntrack dump failed", "err", d.err)
		return
	}
	if !d.res.Complete {
		r.m.Count("dump_incomplete", 1)
	}
	applied := r.m.ApplyDump(d.res)
	if d.res.Complete && d.res.Epoch == r.epoch && r.sub != nil && r.retry == nil {
		r.failures = 0
		if r.m.HasOpenGap(model.GapMap) {
			r.m.CloseGap(model.GapMap, now())
		}
	}
	if applied && d.res.Complete && !r.ready {
		r.ready = true
		r.refreshExporter()
	}
	if r.raw != nil {
		r.rawWrite(map[string]any{"at": d.res.Finished, "run_id": r.runID, "epoch": d.res.Epoch, "source": "dump",
			"attempt": d.res.Attempt, "complete": d.res.Complete, "flows": len(d.res.Flows)})
	}
}

func (r *runner) collectSockets(now time.Time) sockDone {
	snap, err := r.src.Sockets(now)
	addrs, aerr := r.src.Addresses()
	if err == nil {
		err = aerr
	}
	return sockDone{snap: snap, addrs: addrs, err: err}
}

func (r *runner) startSockets() {
	if r.busy["sock"] {
		r.m.Count("skipped_sock", 1)
		return
	}
	r.begin("sock")
	go func() { r.sockC <- r.collectSockets(now()) }()
}

func (r *runner) applySockets(s sockDone) {
	if len(s.addrs) > 0 {
		r.m.SetAddresses(s.addrs, s.snap.At)
	}
	if s.err != nil {
		r.m.Count("sockdiag_errors", 1)
		r.setAttribution(&r.sockFailing, true, "sockdiag_failed")
		return
	}
	if !s.snap.Complete {
		r.m.Count("sockdiag_incomplete", 1)
	}
	r.setAttribution(&r.sockFailing, false, "")
	r.m.ApplySockets(s.snap)
}

func (r *runner) collectProcs(now time.Time) procDone {
	idx, st, err := r.src.Procs(now)
	return procDone{idx, st, err}
}

func (r *runner) startProcs() {
	if r.busy["proc"] {
		r.m.Count("skipped_proc", 1)
		return
	}
	r.begin("proc")
	go func() { r.procC <- r.collectProcs(now()) }()
}

func (r *runner) applyProcs(p procDone) {
	r.m.Count("proc_transient_misses", uint64(p.st.TransientMisses))
	r.m.Count("proc_errors", uint64(p.st.Errors))
	if p.err != nil {
		r.setAttribution(&r.procFailing, true, "proc_failed")
		return
	}
	r.setAttribution(&r.procFailing, false, "")
	r.m.ApplyProcIndex(p.idx)
}

func (r *runner) setAttribution(flag *bool, failing bool, why string) {
	*flag = failing
	now := now()
	open := r.m.HasOpenGap(model.GapAttribution)
	switch {
	case (r.sockFailing || r.procFailing) && !open:
		r.m.OpenGap(model.GapAttribution, why, now)
	case !r.sockFailing && !r.procFailing && open:
		r.m.CloseGap(model.GapAttribution, now)
	}
}

func (r *runner) file() *checkpoint.File {
	st := r.m.Snapshot()
	r.gen++
	f := &checkpoint.File{
		SchemaVersion: checkpoint.SchemaVersion,
		Tool:          checkpoint.Tool{Version: r.cfg.Version, Commit: r.cfg.Commit},
		Host: checkpoint.Host{Hostname: r.info.Hostname, MachineID: r.info.MachineID, BootID: r.info.BootID,
			Kernel: r.info.Kernel, Addresses: st.Addresses},
		Run: checkpoint.Run{RunID: r.runID, StartedAt: r.started, CheckpointAt: now(), Generation: r.gen,
			Params: r.cfg.Params},
		Coverage:     st.Coverage,
		Limits:       st.Limits,
		Dependencies: st.Dependencies,
	}
	if r.lastOK != nil {
		t := *r.lastOK
		f.Run.LastSuccessfulCheckpoint = &t
	}
	return f
}

func (r *runner) startCheckpoint() {
	if r.busy["ck"] {
		r.m.Count("skipped_checkpoint", 1)
		return
	}
	r.begin("ck")
	f := r.file()
	go func() {
		_, err := r.cfg.Write(r.cfg.StateDir, f)
		r.ckC <- err
	}()
}

func (r *runner) checkpointDone(err error) {
	if err != nil {
		r.m.Count("checkpoint_errors", 1)
		r.log.Error("checkpoint write failed", "err", err, "last_successful", r.lastOK)
		return
	}
	t := now()
	r.lastOK = &t
	r.written = true
	if r.cfg.Exporter != nil {
		r.cfg.Exporter.CheckpointWritten(t)
	}
}

// refreshExporter samples active connections on the loop goroutine; it runs on its own
// timer, so a failing socket snapshot does not stop it.
func (r *runner) refreshExporter() {
	if r.cfg.Exporter == nil {
		return
	}
	r.cfg.Exporter.Refresh(r.m.ActiveLabels(), r.m.Health(), r.ready, now())
}

// shutdown follows the order in the design: stop the listener while draining it, collect
// in-flight work, then write the final checkpoint.
func (r *runner) shutdown() int {
	start := time.Now()
	stage := func(name string) { r.log.Info("shutdown", "stage", name, "elapsed", time.Since(start).String()) }
	code := ExitOK
	if r.fatal {
		code = ExitRuntime
	}
	stage("stop observed")
	r.closeSub(r.cfg.ShutdownTimeout)
	stage("subscription close handled")
	wait := time.NewTimer(r.cfg.ShutdownTimeout)
	defer wait.Stop()
	for r.busy["dump"] || r.busy["sock"] || r.busy["proc"] || r.busy["ck"] {
		select {
		case d := <-r.dumpC:
			r.done("dump")
			r.applyDump(d)
		case s := <-r.sockC:
			r.done("sock")
			r.applySockets(s)
		case p := <-r.procC:
			r.done("proc")
			r.applyProcs(p)
		case err := <-r.ckC:
			r.done("ck")
			r.checkpointDone(err)
		case <-wait.C:
			r.log.Error("in-flight work did not finish before the shutdown timeout; writing what was collected")
			for _, k := range []string{"dump", "sock", "proc", "ck"} {
				if r.busy[k] {
					r.markStuck(k)
					r.busy[k] = false
				}
			}
			code = ExitRuntime
		}
	}
	stage("in-flight results handled")
	end := now()
	for _, k := range []model.GapKind{model.GapMap, model.GapAttribution} {
		if r.m.HasOpenGap(k) {
			r.m.CloseGap(k, end)
		}
	}
	r.m.EndInterval(end)
	if r.cfg.NoCheckpoint {
		stage("done without checkpoint")
		r.closeRaw()
		return code
	}
	if _, err := r.cfg.Write(r.cfg.StateDir, r.file()); err != nil {
		r.log.Error("final checkpoint write failed", "err", err, "last_successful", r.lastOK)
		return ExitRuntime
	}
	r.written = true
	stage("final checkpoint written")
	r.closeRaw()
	return code
}

func (r *runner) closeRaw() {
	if r.raw != nil {
		if err := r.raw.Close(); err != nil {
			r.log.Warn("raw journal close failed", "err", err)
		}
	}
}
