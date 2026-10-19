package flows

import (
	"testing"

	"github.com/lavr/ip-connection-explorer/internal/model"
)

func withID(f CTFlow, id uint32) CTFlow { f.ID = id; return f }

func TestBaselineThenLateNewSameLifetime(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.SetEpoch(1)
	f := withID(flow(model.ProtoTCP, "192.0.2.10:40000", "198.51.100.5:443"), 7)
	m.ApplyDump(DumpResult{Attempt: 1, Epoch: 1, Started: at(1), Finished: at(2), Flows: []CTFlow{f}, Complete: true, Baseline: true})
	m.ApplyEvent(newEvent(f, 3))
	m.ApplyEvent(newEvent(f, 4))
	if d := onlyDep(t, m); d.FlowsObserved != 1 {
		t.Fatalf("flows=%d", d.FlowsObserved)
	}
}

func TestNewWithDifferentIDIsNewLifetime(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.SetEpoch(1)
	f := flow(model.ProtoTCP, "192.0.2.10:40000", "198.51.100.5:443")
	m.ApplyEvent(newEvent(withID(f, 7), 1))
	m.ApplyEvent(newEvent(withID(f, 8), 2))
	if d := onlyDep(t, m); d.FlowsObserved != 2 {
		t.Fatalf("flows=%d", d.FlowsObserved)
	}
}

func TestDumpRemovalThenLateDestroy(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.SetEpoch(1)
	f := withID(flow(model.ProtoTCP, "192.0.2.10:40000", "198.51.100.5:443"), 7)
	m.ApplyEvent(newEvent(f, 1))
	m.ApplyDump(DumpResult{Attempt: 1, Epoch: 1, Started: at(2), Finished: at(3), Complete: true})
	m.ApplyEvent(destroyEvent(f, 4))
	if d := onlyDep(t, m); d.FlowsObserved != 1 || m.ActiveCount() != 0 {
		t.Fatalf("flows=%d active=%d", d.FlowsObserved, m.ActiveCount())
	}
}

func TestLowConfidenceUDPPreservesSourcePorts(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.SetEpoch(1)
	for i, src := range []string{"192.0.2.10:40000", "192.0.2.10:40001"} {
		m.ApplyEvent(CTEvent{Kind: EventNew, At: at(i), Epoch: 1, Flow: flow(model.ProtoUDP, src, "198.51.100.53:53")})
	}
	ds := deps(m)
	if len(ds) != 2 {
		t.Fatalf("want 2 keys, got %d", len(ds))
	}
	for _, d := range ds {
		if d.Key.A.Port == 0 || d.Key.B.Port != 53 || d.Confidence != model.ConfidenceLow {
			t.Fatalf("%+v", d.Key)
		}
	}
}

func TestLowConfidenceCountsAgainstUnknownBudget(t *testing.T) {
	lim := bigLimits
	lim.MaxUnknown = 1
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, lim)
	m.SetEpoch(1)
	m.ApplyEvent(CTEvent{Kind: EventNew, At: at(1), Epoch: 1, Flow: flow(model.ProtoUDP, "192.0.2.10:40000", "198.51.100.53:53")})
	m.ApplyEvent(CTEvent{Kind: EventNew, At: at(2), Epoch: 1, Flow: flow(model.ProtoUDP, "192.0.2.10:40001", "198.51.100.53:53")})
	if s := m.Snapshot(); len(s.Dependencies) != 1 || !s.Limits.UnknownTruncated || s.Limits.Truncated {
		t.Fatalf("%+v", s.Limits)
	}
}

func TestStaleProcessSnapshotNotUsed(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.SetEpoch(1)
	m.ApplySockets(SockSnapshot{At: at(0), Complete: true, Sockets: []Socket{
		{Proto: model.ProtoTCP, Local: ep("192.0.2.10:40000"), Remote: ep("198.51.100.5:443"), State: model.SockEstablished, Inode: 1}}})
	m.ApplyProcIndex(ProcIndex{At: at(0), ByInode: map[uint32][]Proc{1: {{PID: 1, Comm: "old-client"}}}})
	m.ApplyEvent(newEvent(flow(model.ProtoTCP, "192.0.2.10:40000", "198.51.100.5:443"), 600))
	if d := onlyDep(t, m); len(d.Processes) != 0 {
		t.Fatalf("%+v", d.Processes)
	}
}

func TestConnectedUDPRespectsPeer(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.SetEpoch(1)
	m.ApplySockets(SockSnapshot{At: at(0), Complete: true, Sockets: []Socket{
		{Proto: model.ProtoUDP, Local: ep("192.0.2.10:40000"), Remote: ep("198.51.100.53:53"), Inode: 1},
		{Proto: model.ProtoUDP, Local: ep("192.0.2.10:40000"), Remote: ep("198.51.100.54:514"), Inode: 2},
	}})
	m.ApplyProcIndex(ProcIndex{At: at(0), ByInode: map[uint32][]Proc{1: {{Comm: "dns-client"}}, 2: {{Comm: "other-peer"}}}})
	m.ApplyEvent(CTEvent{Kind: EventNew, At: at(1), Epoch: 1, Flow: flow(model.ProtoUDP, "192.0.2.10:40000", "198.51.100.53:53")})
	d := onlyDep(t, m)
	if len(d.Processes) != 1 || d.Processes[0].Comm != "dns-client" {
		t.Fatalf("%+v", d.Processes)
	}
}

func TestActiveProcessCap(t *testing.T) {
	lim := bigLimits
	lim.MaxProcesses = 1
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, lim)
	m.SetEpoch(1)
	f := flow(model.ProtoUDP, "192.0.2.10:40000", "198.51.100.53:53")
	m.ApplyEvent(CTEvent{Kind: EventNew, At: at(1), Epoch: 1, Flow: f})
	m.ApplySockets(SockSnapshot{At: at(1), Complete: true, Sockets: []Socket{{Proto: model.ProtoUDP, Local: ep("192.0.2.10:40000"), Inode: 1}}})
	for i := 0; i < 100; i++ {
		m.ApplyProcIndex(ProcIndex{At: at(1), ByInode: map[uint32][]Proc{1: {{Comm: string(rune('a'+i%26)) + string(rune('a'+i/26))}}}})
	}
	for _, af := range m.active {
		if len(af.procOrder) > 1 || !af.procsTrunc {
			t.Fatalf("active procs=%d trunc=%v", len(af.procOrder), af.procsTrunc)
		}
	}
	if d := onlyDep(t, m); !d.ProcessesTruncated {
		t.Fatal("not truncated")
	}
}

func TestProcessRenormalizesOnReclassify(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.SetEpoch(1)
	m.ApplySockets(SockSnapshot{At: at(0), Complete: true, Sockets: []Socket{
		{Proto: model.ProtoTCP, Local: ep("192.0.2.10:40000"), Remote: ep("198.51.100.5:443"), State: model.SockEstablished, Inode: 1}}})
	m.ApplyProcIndex(ProcIndex{At: at(0), ByInode: map[uint32][]Proc{1: {{Comm: "client"}}}})
	m.ApplyEvent(newEvent(flow(model.ProtoTCP, "192.0.2.10:40000", "198.51.100.5:443"), 1))
	m.ApplySockets(SockSnapshot{At: at(2), Complete: true, Sockets: []Socket{
		{Proto: model.ProtoTCP, Local: ep("192.0.2.10:40000"), Remote: ep("198.51.100.5:443"), State: model.SockEstablished, Inode: 1},
		listen(model.ProtoTCP, "0.0.0.0:40000")}})
	d := onlyDep(t, m)
	if len(d.Processes) != 1 {
		t.Fatalf("%+v", d.Processes)
	}
}

func TestOppositeUnknownOrientationsSeparate(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.SetEpoch(1)
	a := flow(model.ProtoUDP, "198.51.100.7:10000", "192.0.2.10:10001")
	b := flow(model.ProtoUDP, "192.0.2.10:10001", "198.51.100.7:10000")
	m.ApplyEvent(CTEvent{Kind: EventNew, At: at(1), Epoch: 1, Flow: a})
	m.ApplyEvent(CTEvent{Kind: EventDestroy, At: at(2), Epoch: 1, Flow: a})
	m.ApplyEvent(CTEvent{Kind: EventNew, At: at(3), Epoch: 1, Flow: b})
	got := map[model.Direction]bool{}
	for _, d := range deps(m) {
		got[d.Direction] = true
	}
	if !got[model.DirInbound] || len(deps(m)) != 2 {
		t.Fatalf("%v", deps(m))
	}
}

func TestSimultaneousOpenWithoutListen(t *testing.T) {
	f := flow(model.ProtoTCP, "192.0.2.10:7000", "198.51.100.7:7001")
	f.TCPState, f.HasTCPState = model.CTSynSent2, true
	inf := classifyAt(f, FlowEvidence{SawNew: true, NewState: model.CTSynSent}, nil, host)
	if inf.Status != model.RoleConflict {
		t.Fatalf("%+v", inf)
	}
	g := flow(model.ProtoTCP, "192.0.2.10:7000", "198.51.100.7:7001")
	inf = classifyAt(g, FlowEvidence{SawSimultaneousOpen: true}, nil, host)
	if inf.Status != model.RoleConflict {
		t.Fatalf("%+v", inf)
	}
}

func TestIPv6WildcardDoesNotRaiseIPv4ToHigh(t *testing.T) {
	f := flow(model.ProtoTCP, "198.51.100.7:51000", "192.0.2.10:5432")
	inf := classifyAt(f, FlowEvidence{}, []Socket{listen(model.ProtoTCP, "[::]:5432")}, host)
	if inf.Confidence != model.ConfidenceMedium || !hasEvidence(inf, model.EvidenceListen) {
		t.Fatalf("%+v", inf)
	}
	g := flow(model.ProtoTCP, "192.0.2.10:5432", "198.51.100.7:51000")
	inf = classifyAt(g, FlowEvidence{}, []Socket{listen(model.ProtoTCP, "[::]:5432")}, host)
	if inf.Status == model.RoleConflict {
		t.Fatalf("assumed dual-stack produced conflict: %+v", inf)
	}
}
