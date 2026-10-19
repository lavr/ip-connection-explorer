package flows

import (
	"net/netip"
	"testing"
	"time"

	"github.com/lavr/ip-connection-explorer/internal/model"
)

var bigLimits = Limits{MaxActive: 1000, MaxKnown: 1000, MaxUnknown: 1000, MaxProcesses: 5, MaxExamples: 3}

func newTestMachine(t *testing.T, machineID string, hostAddrs []string, lim Limits) *Machine {
	t.Helper()
	h := host
	h.MachineID = machineID
	m := NewMachine(h, model.ObserverRef{Hostname: "h-" + machineID, MachineID: machineID, RunID: "r1"}, lim, 2*time.Minute, 10*time.Minute)
	if hostAddrs != nil {
		var as []netip.Addr
		for _, s := range hostAddrs {
			as = append(as, netip.MustParseAddr(s))
		}
		m.SetAddresses(as, t0)
	}
	return m
}

func at(sec int) time.Time { return t0.Add(time.Duration(sec) * time.Second) }

func newEvent(f CTFlow, sec int) CTEvent {
	f.TCPState, f.HasTCPState = model.CTSynSent, true
	return CTEvent{Kind: EventNew, At: at(sec), Epoch: 1, Flow: f}
}

func destroyEvent(f CTFlow, sec int) CTEvent {
	return CTEvent{Kind: EventDestroy, At: at(sec), Epoch: 1, Flow: f}
}

func deps(m *Machine) []model.Dependency { return m.Snapshot().Dependencies }

func onlyDep(t *testing.T, m *Machine) model.Dependency {
	t.Helper()
	d := deps(m)
	if len(d) != 1 {
		t.Fatalf("want 1 dependency, got %d: %+v", len(d), d)
	}
	return d[0]
}

func TestLateDumpDoesNotResurrect(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.SetEpoch(1)
	f := flow(model.ProtoTCP, "192.0.2.10:40000", "198.51.100.5:443")
	m.ApplyEvent(newEvent(f, 1))
	m.ApplyEvent(destroyEvent(f, 2))
	m.ApplyDump(DumpResult{Attempt: 1, Epoch: 1, Started: at(0), Finished: at(3), Flows: []CTFlow{f}, Complete: true})
	if n := m.ActiveCount(); n != 0 {
		t.Fatalf("active=%d", n)
	}
	if d := onlyDep(t, m); d.FlowsObserved != 1 {
		t.Fatalf("flows=%d", d.FlowsObserved)
	}
}

func TestNewAfterDestroyIsNewLifetime(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.SetEpoch(1)
	f := flow(model.ProtoTCP, "192.0.2.10:40000", "198.51.100.5:443")
	m.ApplyEvent(newEvent(f, 1))
	m.ApplyEvent(destroyEvent(f, 2))
	m.ApplyEvent(newEvent(f, 3))
	d := onlyDep(t, m)
	if d.FlowsObserved != 2 || d.NewEvents != 2 || d.DestroyEvents != 1 {
		t.Fatalf("%+v", d)
	}
}

func TestRepeatedResyncDoesNotGrowCount(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.SetEpoch(1)
	f := flow(model.ProtoTCP, "198.51.100.7:51000", "192.0.2.10:5432")
	for i := 1; i <= 3; i++ {
		m.ApplyDump(DumpResult{Attempt: uint64(i), Epoch: 1, Started: at(i * 10), Finished: at(i*10 + 1), Flows: []CTFlow{f}, Complete: true, Baseline: i == 1})
	}
	d := onlyDep(t, m)
	if d.FlowsObserved != 1 {
		t.Fatalf("flows=%d", d.FlowsObserved)
	}
	if !hasSource(d, model.SourceDump) || !hasSource(d, model.SourceBaseline) {
		t.Fatalf("sources=%v", d.Sources)
	}
	if d.Direction != model.DirInbound || d.Key.Service != netip.MustParseAddr("192.0.2.10") {
		t.Fatalf("%+v", d)
	}
}

func hasSource(d model.Dependency, s model.Source) bool {
	for _, x := range d.Sources {
		if x == s {
			return true
		}
	}
	return false
}

func TestStaleEpochIgnored(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.SetEpoch(2)
	f := flow(model.ProtoTCP, "192.0.2.10:40000", "198.51.100.5:443")
	m.ApplyDump(DumpResult{Attempt: 5, Epoch: 1, Started: at(0), Finished: at(1), Flows: []CTFlow{f}, Complete: true})
	ev := newEvent(f, 2)
	ev.Epoch = 1
	m.ApplyEvent(ev)
	if len(deps(m)) != 0 || m.ActiveCount() != 0 {
		t.Fatal("stale input applied")
	}
}

func TestStaleAttemptIgnored(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.SetEpoch(1)
	f := flow(model.ProtoTCP, "192.0.2.10:40000", "198.51.100.5:443")
	m.ApplyDump(DumpResult{Attempt: 2, Epoch: 1, Started: at(10), Finished: at(11), Complete: true})
	m.ApplyDump(DumpResult{Attempt: 1, Epoch: 1, Started: at(0), Finished: at(1), Flows: []CTFlow{f}, Complete: true})
	if m.ActiveCount() != 0 {
		t.Fatal("older attempt applied")
	}
}

func TestPartialDumpDoesNotRemove(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.SetEpoch(1)
	f := flow(model.ProtoTCP, "192.0.2.10:40000", "198.51.100.5:443")
	m.ApplyEvent(newEvent(f, 1))
	m.ApplyDump(DumpResult{Attempt: 1, Epoch: 1, Started: at(5), Finished: at(6), Complete: false})
	if m.ActiveCount() != 1 {
		t.Fatal("partial dump removed flow")
	}
	m.ApplyDump(DumpResult{Attempt: 2, Epoch: 1, Started: at(7), Finished: at(8), Complete: true})
	if m.ActiveCount() != 0 {
		t.Fatal("complete dump kept absent flow")
	}
	if d := onlyDep(t, m); d.FlowsObserved != 1 {
		t.Fatalf("flows=%d", d.FlowsObserved)
	}
}

func TestEventAfterDumpStartNotRemoved(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.SetEpoch(1)
	f := flow(model.ProtoTCP, "192.0.2.10:40000", "198.51.100.5:443")
	m.ApplyEvent(newEvent(f, 6))
	m.ApplyDump(DumpResult{Attempt: 1, Epoch: 1, Started: at(5), Finished: at(7), Complete: true})
	if m.ActiveCount() != 1 {
		t.Fatal("flow created during dump was removed")
	}
}

func TestUnknownToKnownMovesAccounting(t *testing.T) {
	m := newTestMachine(t, "m1", nil, bigLimits)
	m.SetEpoch(1)
	f := flow(model.ProtoUDP, "192.0.2.10:40000", "198.51.100.53:53")
	m.ApplyEvent(CTEvent{Kind: EventNew, At: at(1), Epoch: 1, Flow: f})
	if d := onlyDep(t, m); d.Key.Status != model.RoleUnknown {
		t.Fatalf("%+v", d.Key)
	}
	m.SetAddresses([]netip.Addr{netip.MustParseAddr("192.0.2.10")}, at(2))
	d := onlyDep(t, m)
	if d.Key.Status != model.RoleKnown || d.FlowsObserved != 1 || d.Key.ServicePort != 53 || d.Confidence != model.ConfidenceLow {
		t.Fatalf("%+v", d)
	}
}

func TestUnknownKeyKeepsOrientation(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.SetEpoch(1)
	f := flow(model.ProtoUDP, "198.51.100.7:40000", "192.0.2.10:5353")
	m.ApplyEvent(CTEvent{Kind: EventNew, At: at(1), Epoch: 1, Flow: f})
	d := onlyDep(t, m)
	if d.Key.A != ep("198.51.100.7:40000") || d.Key.B != ep("192.0.2.10:5353") || d.Orientation == nil || d.Orientation.Src != ep("198.51.100.7:40000") {
		t.Fatalf("%+v %+v", d.Key, d.Orientation)
	}
}

func TestDirectionPerObserver(t *testing.T) {
	f := flow(model.ProtoTCP, "192.0.2.10:40000", "198.51.100.5:443")
	a := newTestMachine(t, "ma", []string{"192.0.2.10"}, bigLimits)
	b := newTestMachine(t, "mb", []string{"198.51.100.5"}, bigLimits)
	for _, m := range []*Machine{a, b} {
		m.SetEpoch(1)
		m.ApplyEvent(newEvent(f, 1))
	}
	if d := onlyDep(t, a); d.Direction != model.DirOutbound {
		t.Fatalf("a: %v", d.Direction)
	}
	if d := onlyDep(t, b); d.Direction != model.DirInbound {
		t.Fatalf("b: %v", d.Direction)
	}
}

func TestLocalhostScopeSeparate(t *testing.T) {
	f := flow(model.ProtoTCP, "127.0.0.1:40000", "127.0.0.1:5432")
	var keys []model.DepKey
	for _, id := range []string{"m1", "m2"} {
		m := newTestMachine(t, id, []string{"127.0.0.1"}, bigLimits)
		m.SetEpoch(1)
		m.ApplyEvent(newEvent(f, 1))
		d := onlyDep(t, m)
		if d.Direction != model.DirLocal {
			t.Fatalf("direction %v", d.Direction)
		}
		keys = append(keys, d.Key)
	}
	if keys[0] == keys[1] || keys[0].Scope != "observer:m1" {
		t.Fatalf("%+v", keys)
	}
}

func TestLocalityAfterAddressChange(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.SetEpoch(1)
	m.SetAddresses([]netip.Addr{netip.MustParseAddr("192.0.2.20")}, at(10))
	m.ApplyEvent(newEvent(flow(model.ProtoTCP, "192.0.2.10:40000", "198.51.100.5:443"), 20))
	if d := onlyDep(t, m); d.Direction != model.DirOutbound {
		t.Fatalf("%v", d.Direction)
	}
	as := m.Snapshot().Addresses
	if len(as) != 2 || as[0].Addr != netip.MustParseAddr("192.0.2.10") || !as[0].LastSeen.Equal(t0) || !as[1].FirstSeen.Equal(at(10)) {
		t.Fatalf("%+v", as)
	}
}

func TestForwardedAndUnresolved(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.SetEpoch(1)
	m.ApplyEvent(newEvent(flow(model.ProtoTCP, "198.51.100.1:40000", "203.0.113.5:443"), 1))
	nat := flow(model.ProtoTCP, "198.51.100.1:40001", "203.0.113.9:80")
	nat.Reply = model.Tuple{Src: ep("192.0.2.10:8080"), Dst: ep("198.51.100.1:40001"), Proto: model.ProtoTCP}
	m.ApplyEvent(newEvent(nat, 2))
	got := map[model.Direction]int{}
	for _, d := range deps(m) {
		got[d.Direction]++
	}
	if got[model.DirForwarded] != 1 || got[model.DirUnresolved] != 1 {
		t.Fatalf("%v", got)
	}
}

func TestZonesAreDistinctFlows(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.SetEpoch(1)
	f := flow(model.ProtoTCP, "192.0.2.10:40000", "198.51.100.5:443")
	g := f
	g.Orig.Zone, g.Reply.Zone = 7, 7
	m.ApplyEvent(newEvent(f, 1))
	m.ApplyEvent(newEvent(g, 1))
	if m.ActiveCount() != 2 {
		t.Fatalf("active=%d", m.ActiveCount())
	}
}

func TestKnownLimitTruncates(t *testing.T) {
	lim := bigLimits
	lim.MaxKnown = 1
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, lim)
	m.SetEpoch(1)
	f1 := flow(model.ProtoTCP, "192.0.2.10:40000", "198.51.100.5:443")
	f2 := flow(model.ProtoTCP, "192.0.2.10:40001", "198.51.100.6:443")
	m.ApplyEvent(newEvent(f1, 1))
	m.ApplyEvent(newEvent(f2, 2))
	m.ApplyEvent(CTEvent{Kind: EventUpdate, At: at(9), Epoch: 1, Flow: f1})
	s := m.Snapshot()
	if len(s.Dependencies) != 1 || !s.Limits.Truncated || s.Limits.DroppedObservations < 1 || s.Limits.TruncatedSince == nil {
		t.Fatalf("%+v", s.Limits)
	}
	if !s.Dependencies[0].LastSeen.Equal(at(9)) {
		t.Fatalf("existing record not updated: %v", s.Dependencies[0].LastSeen)
	}
}

func TestActiveLimitRefusesNewFlows(t *testing.T) {
	lim := bigLimits
	lim.MaxActive = 1
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, lim)
	m.SetEpoch(1)
	m.ApplyEvent(newEvent(flow(model.ProtoTCP, "192.0.2.10:40000", "198.51.100.5:443"), 1))
	m.ApplyEvent(newEvent(flow(model.ProtoTCP, "192.0.2.10:40001", "198.51.100.5:443"), 2))
	s := m.Snapshot()
	if m.ActiveCount() != 1 || !s.Limits.Truncated || s.Limits.DroppedObservations != 1 {
		t.Fatalf("active=%d %+v", m.ActiveCount(), s.Limits)
	}
}

func TestUnknownBudgetSeparate(t *testing.T) {
	lim := bigLimits
	lim.MaxUnknown = 1
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, lim)
	m.SetEpoch(1)
	m.ApplyEvent(CTEvent{Kind: EventNew, At: at(1), Epoch: 1, Flow: flow(model.ProtoUDP, "198.51.100.7:40000", "192.0.2.10:5353")})
	m.ApplyEvent(CTEvent{Kind: EventNew, At: at(2), Epoch: 1, Flow: flow(model.ProtoUDP, "198.51.100.8:40000", "192.0.2.10:5353")})
	m.ApplyEvent(newEvent(flow(model.ProtoTCP, "192.0.2.10:40000", "198.51.100.5:443"), 3))
	s := m.Snapshot()
	if len(s.Dependencies) != 2 || !s.Limits.UnknownTruncated || s.Limits.Truncated {
		t.Fatalf("deps=%d %+v", len(s.Dependencies), s.Limits)
	}
}

func TestMapGapMarksHistoryIncomplete(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.OpenGap(model.GapAttribution, "proc", at(1))
	m.CloseGap(model.GapAttribution, at(2))
	if m.Snapshot().Coverage.HistoryIncomplete {
		t.Fatal("attribution gap made map incomplete")
	}
	m.OpenGap(model.GapMap, "enobufs", at(3))
	m.CloseGap(model.GapMap, at(4))
	c := m.Snapshot().Coverage
	if !c.HistoryIncomplete || len(c.Gaps) != 2 || c.Gaps[1].To.IsZero() || c.Gaps[1].Reason != "enobufs" {
		t.Fatalf("%+v", c)
	}
}

func TestMapGapMarksFlowsEstimated(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.SetEpoch(1)
	m.ApplyEvent(newEvent(flow(model.ProtoTCP, "192.0.2.10:40000", "198.51.100.5:443"), 1))
	m.OpenGap(model.GapMap, "enobufs", at(2))
	if d := onlyDep(t, m); !d.FlowsEstimated {
		t.Fatal("not estimated")
	}
}

func TestProcessAttributionTruncates(t *testing.T) {
	lim := bigLimits
	lim.MaxProcesses = 1
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, lim)
	m.SetEpoch(1)
	m.ApplySockets(SockSnapshot{At: at(0), Complete: true, Sockets: []Socket{
		{Proto: model.ProtoTCP, Local: ep("192.0.2.10:40000"), Remote: ep("198.51.100.5:443"), State: model.SockEstablished, Inode: 1},
		{Proto: model.ProtoTCP, Local: ep("192.0.2.10:40001"), Remote: ep("198.51.100.5:443"), State: model.SockEstablished, Inode: 2},
	}})
	m.ApplyProcIndex(ProcIndex{At: at(0), ByInode: map[uint32][]Proc{1: {{PID: 10, Comm: "curl"}}, 2: {{PID: 11, Comm: "wget"}}}})
	m.ApplyEvent(newEvent(flow(model.ProtoTCP, "192.0.2.10:40000", "198.51.100.5:443"), 1))
	m.ApplyEvent(newEvent(flow(model.ProtoTCP, "192.0.2.10:40001", "198.51.100.5:443"), 1))
	d := onlyDep(t, m)
	if len(d.Processes) != 1 || !d.ProcessesTruncated || d.Processes[0].Endpoint.Port != 0 {
		t.Fatalf("%+v", d.Processes)
	}
}

func TestProcessAttributionServiceSide(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.SetEpoch(1)
	f := flow(model.ProtoTCP, "198.51.100.7:51000", "192.0.2.10:5432")
	m.ApplyEvent(newEvent(f, 1))
	m.ApplySockets(SockSnapshot{At: at(2), Complete: true, Sockets: []Socket{
		{Proto: model.ProtoTCP, Local: ep("192.0.2.10:5432"), Remote: ep("198.51.100.7:51000"), State: model.SockEstablished, Inode: 9},
		listen(model.ProtoTCP, "0.0.0.0:5432"),
	}})
	m.ApplyProcIndex(ProcIndex{At: at(2), ByInode: map[uint32][]Proc{9: {{PID: 5, Comm: "postgres"}}}})
	d := onlyDep(t, m)
	if len(d.Processes) != 1 || d.Processes[0].Comm != "postgres" || d.Processes[0].Endpoint != ep("192.0.2.10:5432") || d.Processes[0].Count != 1 {
		t.Fatalf("%+v", d.Processes)
	}
}

func TestExamplesBounded(t *testing.T) {
	lim := bigLimits
	lim.MaxExamples = 2
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, lim)
	m.SetEpoch(1)
	for p := 0; p < 4; p++ {
		f := flow(model.ProtoTCP, netip.AddrPortFrom(netip.MustParseAddr("192.0.2.10"), uint16(40000+p)).String(), "198.51.100.5:443")
		m.ApplyEvent(newEvent(f, p))
	}
	d := onlyDep(t, m)
	if len(d.Examples) != 2 || d.FlowsObserved != 4 {
		t.Fatalf("examples=%d flows=%d", len(d.Examples), d.FlowsObserved)
	}
}

func TestSnapshotIsDeepCopy(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.SetEpoch(1)
	m.ApplyEvent(newEvent(flow(model.ProtoTCP, "192.0.2.10:40000", "198.51.100.5:443"), 1))
	s := m.Snapshot()
	s.Dependencies[0].Sources[0] = model.SourceSockdiag
	s.Coverage.Counters["x"] = 1
	s2 := m.Snapshot()
	if s2.Dependencies[0].Sources[0] == model.SourceSockdiag || s2.Coverage.Counters["x"] == 1 {
		t.Fatal("snapshot shares memory")
	}
}
