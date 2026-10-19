package flows

import (
	"fmt"
	"testing"
	"time"

	"github.com/lavr/ip-connection-explorer/internal/model"
)

func udpEvent(src, dst string, sec int) CTEvent {
	return CTEvent{Kind: EventNew, At: at(sec), Epoch: 1, Flow: flow(model.ProtoUDP, src, dst)}
}

func TestDNSClientDoesNotExhaustBudget(t *testing.T) {
	lim := bigLimits
	lim.MaxUnknown, lim.MaxKnown = 10, 10
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, lim)
	m.SetEpoch(1)
	for i := 0; i < 600; i++ {
		m.ApplyEvent(udpEvent(fmt.Sprintf("192.0.2.10:%d", 33000+i), "198.51.100.53:53", i))
	}
	m.ApplyEvent(udpEvent("192.0.2.10:40999", "198.51.100.77:514", 700))
	s := m.Snapshot()
	if len(s.Dependencies) != 2 || s.Limits.UnknownTruncated || s.Limits.Truncated {
		t.Fatalf("deps=%d limits=%+v", len(s.Dependencies), s.Limits)
	}
	for _, d := range s.Dependencies {
		if d.Key.Service.String() == "198.51.100.53" && d.FlowsObserved != 600 {
			t.Fatalf("flows=%d", d.FlowsObserved)
		}
	}
}

func TestUDPServerInboundCollapses(t *testing.T) {
	lim := bigLimits
	lim.MaxUnknown, lim.MaxKnown = 10, 10
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, lim)
	m.SetEpoch(1)
	m.ApplySockets(SockSnapshot{At: at(0), Complete: true, Sockets: []Socket{{Proto: model.ProtoUDP, Local: ep("0.0.0.0:53")}}})
	for i := 0; i < 600; i++ {
		m.ApplyEvent(udpEvent(fmt.Sprintf("198.51.100.%d:%d", 1+i%3, 1024+i), "192.0.2.10:53", 1))
	}
	s := m.Snapshot()
	if s.Limits.UnknownTruncated || s.Limits.Truncated || len(s.Dependencies) != 3 {
		t.Fatalf("deps=%d %+v", len(s.Dependencies), s.Limits)
	}
	for _, d := range s.Dependencies {
		if d.Key.Status != model.RoleKnown || d.Key.ServicePort != 53 || !hasEvidenceDep(d, model.EvidenceUDPBound) || d.Direction != model.DirInbound {
			t.Fatalf("%+v", d)
		}
	}
}

func TestUDPBoundEphemeralPortIsNotService(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.SetEpoch(1)
	m.ApplySockets(SockSnapshot{At: at(0), Complete: true, Sockets: []Socket{{Proto: model.ProtoUDP, Local: ep("0.0.0.0:40000")}}})
	m.ApplyEvent(udpEvent("198.51.100.53:53", "192.0.2.10:40000", 1))
	if d := onlyDep(t, m); d.Key.Status == model.RoleKnown && d.Key.Service.String() == "192.0.2.10" {
		t.Fatalf("ephemeral bound port became a service: %+v", d.Key)
	}
}

func hasEvidenceDep(d model.Dependency, e model.Evidence) bool {
	for _, x := range d.Evidence {
		if x == e {
			return true
		}
	}
	return false
}

func TestTombstonesBounded(t *testing.T) {
	lim := bigLimits
	lim.MaxActive = 10
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, lim)
	m.SetEpoch(1)
	for i := 0; i < 100; i++ {
		f := flow(model.ProtoTCP, fmt.Sprintf("192.0.2.10:%d", 40000+i), "198.51.100.5:443")
		m.ApplyEvent(newEvent(f, 1))
		m.ApplyEvent(destroyEvent(f, 1))
	}
	if len(m.tombs) > 10 {
		t.Fatalf("tombs=%d", len(m.tombs))
	}
}

func TestTombstonesPurgedByEvents(t *testing.T) {
	h := host
	m := NewMachine(h, model.ObserverRef{MachineID: "m1"}, bigLimits, time.Minute, time.Second)
	m.SetAddresses(nil, t0)
	m.SetEpoch(1)
	f := flow(model.ProtoTCP, "192.0.2.10:40000", "198.51.100.5:443")
	m.ApplyEvent(newEvent(f, 0))
	m.ApplyEvent(destroyEvent(f, 0))
	for i := 0; i < 2000; i++ {
		g := flow(model.ProtoTCP, "192.0.2.10:50000", "198.51.100.6:443")
		m.ApplyEvent(CTEvent{Kind: EventUpdate, At: at(10), Epoch: 1, Flow: g})
	}
	if _, ok := m.tombs[idOf(f)]; ok {
		t.Fatal("expired tombstone kept without dumps")
	}
}

func TestReclassifyIntoFullBudgetKeepsOld(t *testing.T) {
	lim := bigLimits
	lim.MaxUnknown = 1
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, lim)
	m.SetEpoch(1)
	m.ApplyEvent(udpEvent("198.51.100.7:40000", "192.0.2.10:7000", 1))
	m.ApplyEvent(newEvent(flow(model.ProtoTCP, "192.0.2.10:40000", "198.51.100.5:443"), 2))
	before := len(deps(m))
	m.ApplySockets(SockSnapshot{At: at(3), Complete: true, Sockets: []Socket{listen(model.ProtoTCP, "0.0.0.0:40000")}})
	if after := len(deps(m)); after != before {
		t.Fatalf("before=%d after=%d", before, after)
	}
}
