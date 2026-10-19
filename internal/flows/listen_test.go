package flows

import (
	"testing"
	"time"

	"github.com/lavr/ip-connection-explorer/internal/model"
)

func TestListenMatchDualStackWildcard(t *testing.T) {
	li := NewListenIndex([]Socket{listen(model.ProtoTCP, "[::]:5432")}, t0)
	if li.Match(model.ProtoTCP, ep("192.0.2.10:5432"), t0, time.Minute) != MatchAssumed {
		t.Error("v4 via [::] should be an assumed match")
	}
	if li.Match(model.ProtoTCP, ep("[2001:db8::10]:5432"), t0, time.Minute) != MatchExact {
		t.Error("v6 should match [::] exactly")
	}
	if li.Match(model.ProtoTCP, ep("192.0.2.10:5433"), t0, time.Minute) != MatchNone {
		t.Error("other port matched")
	}
	if li.Match(model.ProtoUDP, ep("192.0.2.10:5432"), t0, time.Minute) != MatchNone {
		t.Error("udp matched")
	}
}

func TestListenMatchExactAddress(t *testing.T) {
	li := NewListenIndex([]Socket{listen(model.ProtoTCP, "192.0.2.11:8080"), listen(model.ProtoTCP, "0.0.0.0:22")}, t0)
	if li.Match(model.ProtoTCP, ep("192.0.2.10:8080"), t0, time.Minute) != MatchNone {
		t.Error("different address matched")
	}
	if li.Match(model.ProtoTCP, ep("192.0.2.11:8080"), t0, time.Minute) != MatchExact {
		t.Error("exact address did not match")
	}
	if li.Match(model.ProtoTCP, ep("192.0.2.10:22"), t0, time.Minute) != MatchExact {
		t.Error("0.0.0.0 did not match v4")
	}
	if li.Match(model.ProtoTCP, ep("[2001:db8::10]:22"), t0, time.Minute) != MatchNone {
		t.Error("0.0.0.0 matched v6")
	}
}

func TestListenIgnoresNonListenAndUDP(t *testing.T) {
	li := NewListenIndex([]Socket{
		{Proto: model.ProtoTCP, Local: ep("192.0.2.10:5000"), Remote: ep("198.51.100.1:443"), State: model.SockEstablished},
		{Proto: model.ProtoUDP, Local: ep("0.0.0.0:53")},
	}, t0)
	if li.Match(model.ProtoTCP, ep("192.0.2.10:5000"), t0, time.Minute) != MatchNone || li.Match(model.ProtoUDP, ep("192.0.2.10:53"), t0, time.Minute) != MatchNone {
		t.Error("non-listen socket matched")
	}
}

func TestListenIndexStale(t *testing.T) {
	li := NewListenIndex([]Socket{listen(model.ProtoTCP, "0.0.0.0:5432")}, t0)
	if li.Match(model.ProtoTCP, ep("192.0.2.10:5432"), t0.Add(3*time.Minute), 2*time.Minute) != MatchNone {
		t.Error("stale index matched")
	}
	var nilIdx *ListenIndex
	if nilIdx.Match(model.ProtoTCP, ep("192.0.2.10:5432"), t0, time.Minute) != MatchNone {
		t.Error("nil index matched")
	}
}
