package flows

import (
	"net/netip"
	"time"

	"github.com/lavr/ip-connection-explorer/internal/model"
)

// Labels identify a connection for the Prometheus exporter. They come from the current
// inference, not from the report record, so a full report budget does not change them.
type Labels struct {
	Role      model.RoleStatus
	Direction model.Direction
	Proto     model.Proto
	Src, Dst  netip.Addr
	DstPort   uint16
}

type Health struct {
	ActiveFlows    int
	GapsOpened     uint64
	OpenGaps       []model.GapKind
	ActiveRejected uint64
}

// OnFinish registers fn to be called once for every active lifetime the machine removes,
// with the time of the event or dump that ended it.
func (m *Machine) OnFinish(fn func(Labels, time.Time)) { m.onFinish = fn }

// DisableReport stops keeping dependency records and closed gaps, for runs that write no
// checkpoint. Classification, active flows and tombstones work as before.
func (m *Machine) DisableReport() { m.noReport = true }

func (m *Machine) ActiveLabels() map[Labels]int {
	out := map[Labels]int{}
	for _, f := range m.active {
		out[f.labels]++
	}
	return out
}

func (m *Machine) Health() Health {
	h := Health{ActiveFlows: len(m.active), GapsOpened: m.gapsOpened, ActiveRejected: m.activeRejected}
	for _, g := range m.cov.Gaps {
		if g.To.IsZero() {
			h.OpenGaps = append(h.OpenGaps, g.Kind)
		}
	}
	return h
}

// labelsFor uses the initiator and service for a known role, and the original orientation
// otherwise, with a local ephemeral port collapsed to 0 as in the report.
func (m *Machine) labelsFor(f *activeFlow) Labels {
	o := f.ct.Orig
	l := Labels{Role: f.inf.Status, Direction: f.dir, Proto: o.Proto}
	if f.inf.Status == model.RoleKnown {
		l.Src = model.NormalizeAddr(f.inf.Initiator.Addr)
		l.Dst = model.NormalizeAddr(f.inf.Service.Addr)
		if !o.Proto.IsICMP() {
			l.DstPort = f.inf.Service.Port
		}
		return l
	}
	dst := m.collapse(o.Proto, normEP(o.Dst))
	l.Src, l.Dst, l.DstPort = model.NormalizeAddr(o.Src.Addr), dst.Addr, dst.Port
	if o.Proto.IsICMP() {
		l.DstPort = 0
	}
	return l
}
