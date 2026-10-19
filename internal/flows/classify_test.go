package flows

import (
	"testing"

	"github.com/lavr/ip-connection-explorer/internal/model"
)

func classifyAt(f CTFlow, ev FlowEvidence, socks []Socket, h HostContext) Inference {
	return Classify(f, ev, NewListenIndex(socks, t0), hostAddrs, h, t0)
}

func TestUDPSendtoClientIsNotService(t *testing.T) {
	f := flow(model.ProtoUDP, "192.0.2.10:53000", "192.0.2.53:53")
	socks := []Socket{{Proto: model.ProtoUDP, Local: ep("192.0.2.10:53000")}}
	inf := classifyAt(f, FlowEvidence{}, socks, host)
	if inf.Status != model.RoleKnown || inf.Service != ep("192.0.2.53:53") || inf.Confidence != model.ConfidenceLow || !hasEvidence(inf, model.EvidencePortRange) {
		t.Fatalf("in range: %+v", inf)
	}
	h := host
	h.PortRangeLow, h.PortRangeHigh = 61000, 65000
	inf = classifyAt(f, FlowEvidence{}, socks, h)
	if inf.Status != model.RoleUnknown {
		t.Fatalf("out of range: %+v", inf)
	}
	if inf.Service == ep("192.0.2.10:53000") {
		t.Fatal("client became service")
	}
}

func TestUDPInboundToBoundPortIsService(t *testing.T) {
	f := flow(model.ProtoUDP, "198.51.100.7:40000", "192.0.2.10:5353")
	inf := classifyAt(f, FlowEvidence{}, []Socket{{Proto: model.ProtoUDP, Local: ep("0.0.0.0:5353")}}, host)
	if inf.Status != model.RoleKnown || inf.Service != ep("192.0.2.10:5353") || !hasEvidence(inf, model.EvidenceUDPBound) || inf.Confidence != model.ConfidenceLow {
		t.Fatalf("%+v", inf)
	}
	if inf = classifyAt(f, FlowEvidence{}, nil, host); inf.Status != model.RoleUnknown {
		t.Fatalf("unbound port: %+v", inf)
	}
}

func TestTCPSourcePortCollidesWithListen(t *testing.T) {
	f := flow(model.ProtoTCP, "192.0.2.10:8080", "198.51.100.20:443")
	ev := FlowEvidence{SawNew: true, NewState: model.CTSynSent}
	inf := classifyAt(f, ev, []Socket{listen(model.ProtoTCP, "192.0.2.11:8080")}, host)
	if inf.Status != model.RoleKnown || inf.Initiator != ep("192.0.2.10:8080") || inf.Service != ep("198.51.100.20:443") || inf.Confidence != model.ConfidenceHigh {
		t.Fatalf("%+v", inf)
	}
}

func TestTCPNewNotSynSentIsMedium(t *testing.T) {
	f := flow(model.ProtoTCP, "198.51.100.7:51000", "192.0.2.10:5432")
	inf := classifyAt(f, FlowEvidence{SawNew: true, NewState: model.CTEstablished}, nil, host)
	if inf.Confidence != model.ConfidenceMedium || !hasEvidence(inf, model.EvidenceConntrackOriginal) {
		t.Fatalf("%+v", inf)
	}
}

func TestTCPBaselineOnlyMedium(t *testing.T) {
	f := flow(model.ProtoTCP, "198.51.100.7:51000", "192.0.2.10:5432")
	inf := classifyAt(f, FlowEvidence{}, nil, host)
	if inf.Status != model.RoleKnown || inf.Service != ep("192.0.2.10:5432") || inf.Confidence != model.ConfidenceMedium || !hasEvidence(inf, model.EvidenceConntrackOriginal) {
		t.Fatalf("%+v", inf)
	}
}

func TestTCPBaselineConfirmedByListen(t *testing.T) {
	f := flow(model.ProtoTCP, "198.51.100.7:51000", "192.0.2.10:5432")
	inf := classifyAt(f, FlowEvidence{}, []Socket{listen(model.ProtoTCP, "0.0.0.0:5432")}, host)
	if inf.Confidence != model.ConfidenceHigh || !hasEvidence(inf, model.EvidenceListen) {
		t.Fatalf("%+v", inf)
	}
}

func TestTCPListenContradicts(t *testing.T) {
	f := flow(model.ProtoTCP, "192.0.2.10:5432", "198.51.100.7:51000")
	inf := classifyAt(f, FlowEvidence{}, []Socket{listen(model.ProtoTCP, "0.0.0.0:5432")}, host)
	if inf.Status != model.RoleConflict || !hasEvidence(inf, model.EvidenceListenContradicts) {
		t.Fatalf("%+v", inf)
	}
}

func TestTCPSimultaneousOpenConflict(t *testing.T) {
	f := flow(model.ProtoTCP, "192.0.2.10:7000", "[2001:db8::10]:7001")
	f.Orig.Dst = ep("192.0.2.10:7001")
	inf := classifyAt(f, FlowEvidence{}, []Socket{listen(model.ProtoTCP, "0.0.0.0:7000"), listen(model.ProtoTCP, "0.0.0.0:7001")}, host)
	if inf.Status != model.RoleConflict {
		t.Fatalf("%+v", inf)
	}
}

func TestICMPKeyedByType(t *testing.T) {
	f := flow(model.ProtoICMP, "192.0.2.10:0", "198.51.100.1:0")
	f.Orig.ICMPType, f.Orig.ICMPCode = 8, 0
	inf := classifyAt(f, FlowEvidence{}, nil, host)
	if inf.Status != model.RoleKnown || inf.Service.Port != 0 || inf.Service.Addr != ep("198.51.100.1:0").Addr || inf.Confidence != model.ConfidenceMedium {
		t.Fatalf("%+v", inf)
	}
}

func TestUnknownProtocol(t *testing.T) {
	f := flow(132, "192.0.2.10:1", "198.51.100.1:2")
	if inf := classifyAt(f, FlowEvidence{}, nil, host); inf.Status != model.RoleUnknown {
		t.Fatalf("%+v", inf)
	}
}
