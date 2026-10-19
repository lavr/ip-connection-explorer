package model

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNormalizeAddrUnmaps(t *testing.T) {
	got := NormalizeAddr(netip.MustParseAddr("::ffff:192.0.2.1"))
	if got != netip.MustParseAddr("192.0.2.1") {
		t.Fatalf("got %v", got)
	}
	v6 := netip.MustParseAddr("2001:db8::1")
	if NormalizeAddr(v6) != v6 {
		t.Fatal("v6 changed")
	}
}

func TestScopeFor(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "::1", "fe80::1", "169.254.1.1", "ff02::1"} {
		if got := ScopeFor(netip.MustParseAddr(s), "m1"); got != "observer:m1" {
			t.Errorf("%s: %s", s, got)
		}
	}
	for _, s := range []string{"192.0.2.1", "2001:db8::1"} {
		if got := ScopeFor(netip.MustParseAddr(s), "m1"); got != "global" {
			t.Errorf("%s: %s", s, got)
		}
	}
}

func TestConfidenceOrderAndText(t *testing.T) {
	if !(ConfidenceLow < ConfidenceMedium && ConfidenceMedium < ConfidenceHigh) {
		t.Fatal("order")
	}
	for _, c := range []Confidence{ConfidenceLow, ConfidenceMedium, ConfidenceHigh} {
		b, err := c.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		var back Confidence
		if err := back.UnmarshalText(b); err != nil || back != c {
			t.Fatalf("%s: %v %v", b, back, err)
		}
	}
	if b, _ := ConfidenceHigh.MarshalText(); string(b) != "high" {
		t.Fatalf("%s", b)
	}
}

func TestEnumRejectsUnknownText(t *testing.T) {
	var c Confidence
	var r RoleStatus
	var e Evidence
	var d Direction
	var s Source
	var g GapKind
	for name, u := range map[string]interface{ UnmarshalText([]byte) error }{
		"confidence": &c, "role": &r, "evidence": &e, "direction": &d, "source": &s, "gap": &g,
	} {
		if err := u.UnmarshalText([]byte("bogus")); err == nil {
			t.Errorf("%s accepted bogus", name)
		}
	}
}

func TestProtoString(t *testing.T) {
	cases := map[Proto]string{ProtoTCP: "tcp", ProtoUDP: "udp", ProtoICMP: "icmp", ProtoICMPv6: "icmpv6", 132: "132"}
	for p, want := range cases {
		if p.String() != want {
			t.Errorf("%d: %s", p, p.String())
		}
	}
}

func TestDependencyJSONRoundtrip(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	orig := Tuple{Src: Endpoint{netip.MustParseAddr("192.0.2.10"), 40000}, Dst: Endpoint{netip.MustParseAddr("198.51.100.5"), 443}, Proto: ProtoTCP}
	d := Dependency{
		Key: DepKey{Scope: "global", Family: 4, Proto: ProtoTCP, Status: RoleKnown,
			Initiator: netip.MustParseAddr("192.0.2.10"), Service: netip.MustParseAddr("198.51.100.5"), ServicePort: 443},
		Observer:      ObserverRef{Hostname: "h", MachineID: "m1", RunID: "r1"},
		Direction:     DirOutbound,
		FirstSeen:     at,
		LastSeen:      at,
		Sources:       []Source{SourceEvent},
		FlowsObserved: 1,
		EverReplySeen: true,
		TCPStates:     []CTState{CTSynSent, CTEstablished},
		Processes:     []ProcessRef{{Comm: "curl", Endpoint: orig.Src, Count: 1}},
		Examples:      []Example{{At: at, Orig: orig, Reply: Tuple{Src: orig.Dst, Dst: orig.Src, Proto: ProtoTCP}}},
		Evidence:      []Evidence{EvidenceConntrackNew},
		Confidence:    ConfidenceHigh,
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"ever_reply_seen":true`, `"confidence":"high"`, `"direction":"outbound"`, `"addr":"192.0.2.10"`} {
		if !strings.Contains(string(b), field) {
			t.Errorf("missing %s in %s", field, b)
		}
	}
	var back Dependency
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(d, back) {
		t.Fatalf("roundtrip mismatch:\n%+v\n%+v", d, back)
	}
}

func TestDepKeyStringStable(t *testing.T) {
	k := DepKey{Scope: "global", Family: 4, Proto: ProtoTCP, Status: RoleKnown,
		Initiator: netip.MustParseAddr("192.0.2.10"), Service: netip.MustParseAddr("198.51.100.5"), ServicePort: 443}
	if k.String() != k.String() || k.String() == "" {
		t.Fatal()
	}
	k2 := k
	k2.ServicePort = 80
	if k.String() == k2.String() {
		t.Fatal("ports not distinguished")
	}
}
