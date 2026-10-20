package flows

import (
	"net/netip"
	"testing"
	"time"

	"github.com/lavr/ip-connection-explorer/internal/model"
)

type finished struct {
	l  Labels
	at time.Time
}

func recordFinish(m *Machine) *[]finished {
	var got []finished
	m.OnFinish(func(l Labels, at time.Time) { got = append(got, finished{l, at}) })
	return &got
}

func labels(role model.RoleStatus, dir model.Direction, p model.Proto, src, dst string, port uint16) Labels {
	return Labels{Role: role, Direction: dir, Proto: p, Src: netip.MustParseAddr(src), Dst: netip.MustParseAddr(dst), DstPort: port}
}

func TestFinishHookOnDestroy(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.SetEpoch(1)
	got := recordFinish(m)
	f := flow(model.ProtoTCP, "192.0.2.10:40000", "198.51.100.5:443")
	m.ApplyEvent(newEvent(f, 1))
	m.ApplyEvent(destroyEvent(f, 2))
	m.ApplyEvent(destroyEvent(f, 3))
	want := labels(model.RoleKnown, model.DirOutbound, model.ProtoTCP, "192.0.2.10", "198.51.100.5", 443)
	if len(*got) != 1 || (*got)[0].l != want || !(*got)[0].at.Equal(at(2)) {
		t.Fatalf("%+v", *got)
	}
}

func TestFinishHookOnCompleteDumpOnly(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.SetEpoch(1)
	got := recordFinish(m)
	f := flow(model.ProtoTCP, "192.0.2.10:40000", "198.51.100.5:443")
	m.ApplyDump(DumpResult{Attempt: 1, Epoch: 1, Started: at(0), Finished: at(1), Flows: []CTFlow{f}, Complete: true})
	m.ApplyDump(DumpResult{Attempt: 2, Epoch: 1, Started: at(10), Finished: at(11), Complete: false})
	if len(*got) != 0 {
		t.Fatalf("partial dump finished a flow: %+v", *got)
	}
	m.ApplyDump(DumpResult{Attempt: 3, Epoch: 1, Started: at(20), Finished: at(21), Complete: true})
	m.ApplyDump(DumpResult{Attempt: 4, Epoch: 1, Started: at(30), Finished: at(31), Complete: true})
	if len(*got) != 1 || !(*got)[0].at.Equal(at(21)) {
		t.Fatalf("%+v", *got)
	}
}

func TestFinishHookIgnoresReportBudget(t *testing.T) {
	lim := bigLimits
	lim.MaxKnown = 1
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, lim)
	m.SetEpoch(1)
	got := recordFinish(m)
	a := flow(model.ProtoTCP, "192.0.2.10:40000", "198.51.100.5:443")
	b := flow(model.ProtoTCP, "192.0.2.10:40001", "198.51.100.6:5432")
	m.ApplyEvent(newEvent(a, 1))
	m.ApplyEvent(newEvent(b, 1))
	m.ApplyEvent(destroyEvent(b, 2))
	want := labels(model.RoleKnown, model.DirOutbound, model.ProtoTCP, "192.0.2.10", "198.51.100.6", 5432)
	if len(*got) != 1 || (*got)[0].l != want {
		t.Fatalf("%+v", *got)
	}
}

func TestActiveLabelsFollowCurrentInference(t *testing.T) {
	lim := bigLimits
	lim.MaxKnown = 1
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, lim)
	m.SetEpoch(1)
	m.ApplyEvent(newEvent(flow(model.ProtoTCP, "192.0.2.10:40000", "198.51.100.5:443"), 1))
	u := flow(model.ProtoUDP, "198.51.100.7:5000", "192.0.2.10:6000")
	m.ApplyEvent(CTEvent{Kind: EventNew, At: at(2), Epoch: 1, Flow: u})
	before := labels(model.RoleUnknown, model.DirInbound, model.ProtoUDP, "198.51.100.7", "192.0.2.10", 6000)
	if n := m.ActiveLabels()[before]; n != 1 {
		t.Fatalf("before: %+v", m.ActiveLabels())
	}
	m.ApplySockets(SockSnapshot{At: at(3), Complete: true, Sockets: []Socket{{Proto: model.ProtoUDP, Local: ep("192.0.2.10:6000")}}})
	after := labels(model.RoleKnown, model.DirInbound, model.ProtoUDP, "198.51.100.7", "192.0.2.10", 6000)
	act := m.ActiveLabels()
	if act[after] != 1 || act[before] != 0 {
		t.Fatalf("after: %+v", act)
	}
	for _, d := range deps(m) {
		if d.Key.Proto == model.ProtoUDP && d.Key.Status != model.RoleUnknown {
			t.Fatalf("report record changed despite the full budget: %+v", d.Key)
		}
	}
}

func TestUnknownLabelsCollapseLocalEphemeralPort(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.SetEpoch(1)
	u := flow(model.ProtoUDP, "198.51.100.7:5000", "192.0.2.10:45000")
	m.ApplyEvent(CTEvent{Kind: EventNew, At: at(1), Epoch: 1, Flow: u})
	want := labels(model.RoleUnknown, model.DirInbound, model.ProtoUDP, "198.51.100.7", "192.0.2.10", 0)
	if m.ActiveLabels()[want] != 1 {
		t.Fatalf("%+v", m.ActiveLabels())
	}
}

func TestICMPLabelsHaveNoPort(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.SetEpoch(1)
	f := CTFlow{Orig: model.Tuple{Src: ep("192.0.2.10:0"), Dst: ep("198.51.100.5:0"), Proto: model.ProtoICMP, ICMPType: 8},
		Reply: model.Tuple{Src: ep("198.51.100.5:0"), Dst: ep("192.0.2.10:0"), Proto: model.ProtoICMP}}
	m.ApplyEvent(CTEvent{Kind: EventNew, At: at(1), Epoch: 1, Flow: f})
	want := labels(model.RoleKnown, model.DirOutbound, model.ProtoICMP, "192.0.2.10", "198.51.100.5", 0)
	if m.ActiveLabels()[want] != 1 {
		t.Fatalf("%+v", m.ActiveLabels())
	}
}

func TestDisableReportKeepsNoRecords(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.DisableReport()
	m.SetEpoch(1)
	got := recordFinish(m)
	for i := range 50 {
		f := flow(model.ProtoTCP, "192.0.2.10:40000", netip.AddrPortFrom(netip.MustParseAddr("198.51.100.5"), uint16(1000+i)).String())
		m.ApplyEvent(newEvent(f, i))
		m.ApplyEvent(destroyEvent(f, i))
	}
	if len(*got) != 50 || len(m.records) != 0 || len(m.refs) != 0 {
		t.Fatalf("finished=%d records=%d refs=%d", len(*got), len(m.records), len(m.refs))
	}
}

func TestDisableReportForgetsClosedGaps(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, bigLimits)
	m.DisableReport()
	for i := range 10 {
		m.OpenGap(model.GapMap, "enobufs", at(2*i))
		m.CloseGap(model.GapMap, at(2*i+1))
	}
	m.OpenGap(model.GapMap, "enobufs", at(100))
	h := m.Health()
	if len(m.cov.Gaps) != 1 || h.GapsOpened != 11 || len(h.OpenGaps) != 1 || h.OpenGaps[0] != model.GapMap {
		t.Fatalf("gaps=%d health=%+v", len(m.cov.Gaps), h)
	}
}

func TestHealthCountsActiveRejections(t *testing.T) {
	lim := bigLimits
	lim.MaxActive = 1
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, lim)
	m.SetEpoch(1)
	m.ApplyEvent(newEvent(flow(model.ProtoTCP, "192.0.2.10:40000", "198.51.100.5:443"), 1))
	m.ApplyEvent(newEvent(flow(model.ProtoTCP, "192.0.2.10:40001", "198.51.100.5:443"), 1))
	if h := m.Health(); h.ActiveFlows != 1 || h.ActiveRejected != 1 {
		t.Fatalf("%+v", h)
	}
}
