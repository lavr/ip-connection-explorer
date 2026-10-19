package flows

import (
	"net/netip"
	"time"

	"github.com/lavr/ip-connection-explorer/internal/model"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func ep(s string) model.Endpoint {
	ap := netip.MustParseAddrPort(s)
	return model.Endpoint{Addr: ap.Addr(), Port: ap.Port()}
}

func tuple(p model.Proto, src, dst string) model.Tuple {
	return model.Tuple{Src: ep(src), Dst: ep(dst), Proto: p}
}

func flow(p model.Proto, src, dst string) CTFlow {
	o := tuple(p, src, dst)
	return CTFlow{Orig: o, Reply: model.Tuple{Src: o.Dst, Dst: o.Src, Proto: p}}
}

type addrs []string

func (a addrs) Has(x netip.Addr) bool {
	for _, s := range a {
		if netip.MustParseAddr(s) == model.NormalizeAddr(x) {
			return true
		}
	}
	return false
}

func listen(p model.Proto, local string) Socket {
	return Socket{Proto: p, Local: ep(local), State: model.SockListen}
}

var host = HostContext{MachineID: "m1", Hostname: "h1", PortRangeLow: 32768, PortRangeHigh: 60999, ListenMaxAge: 2 * time.Minute}
var hostAddrs = addrs{"192.0.2.10", "2001:db8::10"}

func hasEvidence(inf Inference, e model.Evidence) bool {
	for _, x := range inf.Evidence {
		if x == e {
			return true
		}
	}
	return false
}
