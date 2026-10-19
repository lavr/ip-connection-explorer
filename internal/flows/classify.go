package flows

import (
	"time"

	"github.com/lavr/ip-connection-explorer/internal/model"
)

func Classify(f CTFlow, ev FlowEvidence, li *ListenIndex, addrs AddrSet, host HostContext, now time.Time) Inference {
	o := f.Orig
	switch {
	case o.Proto == model.ProtoTCP:
		return classifyTCP(f, ev, li, addrs, host, now)
	case o.Proto == model.ProtoUDP:
		if addrs.Has(o.Src.Addr) && host.PortRangeLow > 0 &&
			o.Src.Port >= host.PortRangeLow && o.Src.Port <= host.PortRangeHigh {
			return Inference{Status: model.RoleKnown, Initiator: o.Src, Service: o.Dst,
				Evidence: []model.Evidence{model.EvidencePortRange}, Confidence: model.ConfidenceLow}
		}
	case o.Proto.IsICMP():
		return Inference{Status: model.RoleKnown,
			Initiator: model.Endpoint{Addr: o.Src.Addr}, Service: model.Endpoint{Addr: o.Dst.Addr},
			Evidence: []model.Evidence{model.EvidenceConntrackOriginal}, Confidence: model.ConfidenceMedium}
	}
	return Inference{Status: model.RoleUnknown, Evidence: []model.Evidence{model.EvidenceNone}, Confidence: model.ConfidenceLow}
}

func classifyTCP(f CTFlow, ev FlowEvidence, li *ListenIndex, addrs AddrSet, host HostContext, now time.Time) Inference {
	o := f.Orig
	inf := Inference{Status: model.RoleKnown, Initiator: o.Src, Service: o.Dst}
	if ev.SawNew && ev.NewState == model.CTSynSent {
		inf.Evidence = []model.Evidence{model.EvidenceConntrackNew}
		inf.Confidence = model.ConfidenceHigh
	} else {
		inf.Evidence = []model.Evidence{model.EvidenceConntrackOriginal}
		inf.Confidence = model.ConfidenceMedium
	}
	if ev.SawSimultaneousOpen || (f.HasTCPState && f.TCPState == model.CTSynSent2) {
		inf.Status = model.RoleConflict
		inf.Confidence = model.ConfidenceLow
		return inf
	}
	dst, src := MatchNone, MatchNone
	if addrs.Has(o.Dst.Addr) {
		dst = li.Match(model.ProtoTCP, o.Dst, now, host.ListenMaxAge)
	}
	if addrs.Has(o.Src.Addr) {
		src = li.Match(model.ProtoTCP, o.Src, now, host.ListenMaxAge)
	}
	switch {
	case src == MatchExact:
		inf.Status = model.RoleConflict
		inf.Evidence = append(inf.Evidence, model.EvidenceListenContradicts)
		inf.Confidence = model.ConfidenceLow
	case dst == MatchExact:
		inf.Evidence = append(inf.Evidence, model.EvidenceListen)
		inf.Confidence = model.ConfidenceHigh
	case dst == MatchAssumed:
		inf.Evidence = append(inf.Evidence, model.EvidenceListen)
	}
	return inf
}
