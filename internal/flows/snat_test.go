package flows

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/lavr/ip-connection-explorer/internal/model"
)

// snatFlow is a pod connection masqueraded behind a host address: the reply comes back to
// the host address and the destination is unchanged.
func snatFlow(p model.Proto, pod, dst, hostEP string) CTFlow {
	o := tuple(p, pod, dst)
	return CTFlow{Orig: o, Reply: model.Tuple{Src: o.Dst, Dst: ep(hostEP), Proto: p}, SrcNAT: true}
}

func TestSNATProjectsToHostAddress(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.SetEpoch(1)
	got := recordFinish(m)
	f := snatFlow(model.ProtoTCP, "10.233.70.5:40000", "198.51.100.6:5432", "192.0.2.10:40000")
	m.ApplyEvent(newEvent(f, 1))
	d := onlyDep(t, m)
	if d.Key.Status != model.RoleKnown || d.Key.Initiator != netip.MustParseAddr("192.0.2.10") ||
		d.Key.Service != netip.MustParseAddr("198.51.100.6") || d.Key.ServicePort != 5432 {
		t.Fatalf("%+v", d.Key)
	}
	if d.Direction != model.DirOutbound || !slices.Contains(d.Evidence, model.EvidenceSNAT) {
		t.Fatalf("%v %v", d.Direction, d.Evidence)
	}
	if len(d.Examples) != 1 || d.Examples[0].Orig != f.Orig || d.Examples[0].Reply != f.Reply {
		t.Fatalf("examples must keep the raw tuples: %+v", d.Examples)
	}
	m.ApplyEvent(destroyEvent(f, 2))
	want := labels(model.RoleKnown, model.DirOutbound, model.ProtoTCP, "192.0.2.10", "198.51.100.6", 5432)
	if len(*got) != 1 || (*got)[0].l != want {
		t.Fatalf("%+v", *got)
	}
}

func TestSNATPodsCollapseToOneDependency(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.SetEpoch(1)
	m.ApplyEvent(newEvent(snatFlow(model.ProtoTCP, "10.233.70.5:40000", "198.51.100.6:5432", "192.0.2.10:40000"), 1))
	m.ApplyEvent(newEvent(snatFlow(model.ProtoTCP, "10.233.70.9:41000", "198.51.100.6:5432", "192.0.2.10:41000"), 1))
	if d := onlyDep(t, m); d.FlowsObserved != 2 {
		t.Fatalf("%+v", d)
	}
	want := labels(model.RoleKnown, model.DirOutbound, model.ProtoTCP, "192.0.2.10", "198.51.100.6", 5432)
	if act := m.ActiveLabels(); len(act) != 1 || act[want] != 2 {
		t.Fatalf("%+v", act)
	}
}

func TestSNATToTwoHostAddressesStaysSeparate(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10", "192.0.2.11"}, bigLimits)
	m.SetEpoch(1)
	m.ApplyEvent(newEvent(snatFlow(model.ProtoTCP, "10.233.70.5:40000", "198.51.100.6:5432", "192.0.2.10:40000"), 1))
	m.ApplyEvent(newEvent(snatFlow(model.ProtoTCP, "10.233.70.9:41000", "198.51.100.6:5432", "192.0.2.11:41000"), 1))
	if n := len(deps(m)); n != 2 {
		t.Fatalf("deps=%d", n)
	}
}

func TestSNATNeedsStatusBit(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.SetEpoch(1)
	f := snatFlow(model.ProtoTCP, "10.233.70.5:40000", "198.51.100.6:5432", "192.0.2.10:40000")
	f.SrcNAT = false
	m.ApplyEvent(newEvent(f, 1))
	if d := onlyDep(t, m); d.Direction != model.DirUnresolved || d.Key.Initiator != netip.MustParseAddr("10.233.70.5") {
		t.Fatalf("%v %+v", d.Direction, d.Key)
	}
	f.SrcNAT = true
	m.ApplyEvent(CTEvent{Kind: EventUpdate, At: at(2), Epoch: 1, Flow: f})
	if d := onlyDep(t, m); d.Direction != model.DirOutbound || d.Key.Initiator != netip.MustParseAddr("192.0.2.10") {
		t.Fatalf("a later status bit did not project: %v %+v", d.Direction, d.Key)
	}
}

func TestDNATIsNotProjected(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.SetEpoch(1)
	f := snatFlow(model.ProtoTCP, "10.233.70.5:40000", "10.233.0.20:443", "192.0.2.10:40000")
	f.Reply.Src = ep("198.51.100.6:8443")
	f.DstNAT = true
	m.ApplyEvent(newEvent(f, 1))
	if d := onlyDep(t, m); d.Direction != model.DirUnresolved || d.Key.Initiator != netip.MustParseAddr("10.233.70.5") {
		t.Fatalf("%v %+v", d.Direction, d.Key)
	}
}

func TestChangedDestinationIsNotProjected(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.SetEpoch(1)
	f := snatFlow(model.ProtoTCP, "10.233.70.5:40000", "198.51.100.6:443", "192.0.2.10:40000")
	f.Reply.Src = ep("198.51.100.6:8443")
	m.ApplyEvent(newEvent(f, 1))
	if d := onlyDep(t, m); d.Direction != model.DirUnresolved {
		t.Fatalf("%v %+v", d.Direction, d.Key)
	}
}

func TestNodePortIsNotProjected(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.SetEpoch(1)
	f := CTFlow{
		Orig:   tuple(model.ProtoTCP, "203.0.113.7:50000", "192.0.2.10:30080"),
		Reply:  tuple(model.ProtoTCP, "10.233.70.9:8080", "192.0.2.10:61000"),
		SrcNAT: true, DstNAT: true,
	}
	m.ApplyEvent(newEvent(f, 1))
	d := onlyDep(t, m)
	if d.Direction != model.DirInbound || d.Key.Initiator != netip.MustParseAddr("203.0.113.7") || d.Key.ServicePort != 30080 {
		t.Fatalf("%v %+v", d.Direction, d.Key)
	}
	if slices.Contains(d.Evidence, model.EvidenceSNAT) {
		t.Fatalf("%v", d.Evidence)
	}
}

func TestSNATOnAddressThatAppearsLater(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.SetEpoch(1)
	m.ApplyEvent(newEvent(snatFlow(model.ProtoTCP, "10.233.70.5:40000", "198.51.100.6:5432", "192.0.2.20:40000"), 1))
	if d := onlyDep(t, m); d.Direction != model.DirForwarded {
		t.Fatalf("%v", d.Direction)
	}
	m.SetAddresses([]netip.Addr{netip.MustParseAddr("192.0.2.20")}, at(2))
	if d := onlyDep(t, m); d.Direction != model.DirOutbound || d.Key.Initiator != netip.MustParseAddr("192.0.2.20") {
		t.Fatalf("%v %+v", d.Direction, d.Key)
	}
}

func TestSNATUDPUsesHostPortRange(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.SetEpoch(1)
	m.ApplyEvent(newEvent(snatFlow(model.ProtoUDP, "10.233.70.5:40000", "198.51.100.53:53", "192.0.2.10:40000"), 1))
	d := onlyDep(t, m)
	if d.Key.Status != model.RoleKnown || d.Key.Initiator != netip.MustParseAddr("192.0.2.10") || d.Key.ServicePort != 53 || d.Direction != model.DirOutbound {
		t.Fatalf("%v %+v", d.Direction, d.Key)
	}
}

func TestOriginalNATViewKeepsPodAddress(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.KeepOriginalNAT()
	m.SetEpoch(1)
	m.ApplyEvent(newEvent(snatFlow(model.ProtoTCP, "10.233.70.5:40000", "198.51.100.6:5432", "192.0.2.10:40000"), 1))
	d := onlyDep(t, m)
	if d.Direction != model.DirUnresolved || d.Key.Initiator != netip.MustParseAddr("10.233.70.5") || slices.Contains(d.Evidence, model.EvidenceSNAT) {
		t.Fatalf("%v %+v %v", d.Direction, d.Key, d.Evidence)
	}
}

func TestSNATRollbackOnFullBudgetKeepsOrientation(t *testing.T) {
	lim := bigLimits
	lim.MaxUnknown = 1
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, lim)
	m.SetEpoch(1)
	f := snatFlow(model.ProtoUDP, "10.233.70.5:1000", "198.51.100.53:1001", "192.0.2.10:1000")
	f.SrcNAT = false
	m.ApplyEvent(newEvent(f, 1))
	f.SrcNAT = true
	m.ApplyEvent(CTEvent{Kind: EventUpdate, At: at(2), Epoch: 1, Flow: f})
	d := onlyDep(t, m)
	if d.Key.A.Addr != netip.MustParseAddr("10.233.70.5") || d.Orientation == nil || d.Orientation.Src.Addr != d.Key.A.Addr {
		t.Fatalf("record and its orientation disagree: %+v %+v", d.Key, d.Orientation)
	}
}
