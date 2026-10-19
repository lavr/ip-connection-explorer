package flows

import (
	"testing"

	"github.com/lavr/ip-connection-explorer/internal/model"
)

func TestTombstoneQueueBounded(t *testing.T) {
	lim := bigLimits
	lim.MaxActive = 10
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, lim)
	m.SetEpoch(1)
	f := flow(model.ProtoTCP, "192.0.2.10:40000", "198.51.100.5:443")
	for i := 0; i < 10000; i++ {
		g := withID(f, uint32(i+1))
		m.ApplyEvent(newEvent(g, 1))
		m.ApplyEvent(destroyEvent(g, 1))
	}
	if len(m.tombQ) > 2*lim.MaxActive+sweepEvery {
		t.Fatalf("tombs=%d queue=%d", len(m.tombs), len(m.tombQ))
	}
}

func TestUDPBoundFamilyMustMatch(t *testing.T) {
	h := host
	v6 := flow(model.ProtoUDP, "[2001:db8::7]:40000", "[2001:db8::10]:5353")
	v4 := flow(model.ProtoUDP, "198.51.100.7:40000", "192.0.2.10:5353")
	cases := []struct {
		name  string
		f     CTFlow
		bound string
		want  model.RoleStatus
	}{
		{"v4 wildcard, v6 flow", v6, "0.0.0.0:5353", model.RoleUnknown},
		{"v6 wildcard, v4 flow", v4, "[::]:5353", model.RoleUnknown},
		{"v6 wildcard, v6 flow", v6, "[::]:5353", model.RoleKnown},
		{"v4 wildcard, v4 flow", v4, "0.0.0.0:5353", model.RoleKnown},
	}
	for _, c := range cases {
		inf := classifyAt(c.f, FlowEvidence{}, []Socket{{Proto: model.ProtoUDP, Local: ep(c.bound)}}, h)
		if inf.Status != c.want {
			t.Errorf("%s: %+v", c.name, inf)
		}
	}
}

func TestFullBudgetKeepsConsistentInference(t *testing.T) {
	lim := bigLimits
	lim.MaxUnknown = 1
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, lim)
	m.SetEpoch(1)
	m.ApplyEvent(udpEvent("198.51.100.7:40000", "192.0.2.10:7000", 1))
	m.ApplyEvent(newEvent(flow(model.ProtoTCP, "192.0.2.10:40000", "198.51.100.5:443"), 2))
	m.ApplySockets(SockSnapshot{At: at(3), Complete: true, Sockets: []Socket{listen(model.ProtoTCP, "0.0.0.0:40000")}})
	for _, d := range deps(m) {
		if d.Key.Status == model.RoleKnown && (hasEvidenceDep(d, model.EvidenceListenContradicts) || d.Confidence != model.ConfidenceHigh) {
			t.Fatalf("known key carries a different inference: %+v %v", d.Evidence, d.Confidence)
		}
	}
}

func TestCollapseKeepsListeningLocalPort(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.SetEpoch(1)
	m.ApplySockets(SockSnapshot{At: at(0), Complete: true, Sockets: []Socket{listen(model.ProtoTCP, "0.0.0.0:40000")}})
	f := flow(model.ProtoTCP, "192.0.2.10:40000", "198.51.100.5:443")
	m.ApplyEvent(newEvent(f, 1))
	d := onlyDep(t, m)
	if d.Key.Status != model.RoleConflict || d.Key.A.Port != 40000 {
		t.Fatalf("%+v", d.Key)
	}
}
