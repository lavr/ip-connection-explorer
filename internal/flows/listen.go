package flows

import (
	"net/netip"
	"time"

	"github.com/lavr/ip-connection-explorer/internal/model"
)

type listenKey struct {
	proto model.Proto
	port  uint16
}

type ListenIndex struct {
	at    time.Time
	addrs map[listenKey][]netip.Addr
}

func NewListenIndex(socks []Socket, at time.Time) *ListenIndex {
	li := &ListenIndex{at: at, addrs: map[listenKey][]netip.Addr{}}
	for _, s := range socks {
		if s.Proto != model.ProtoTCP || s.State != model.SockListen {
			continue
		}
		k := listenKey{s.Proto, s.Local.Port}
		li.addrs[k] = append(li.addrs[k], model.NormalizeAddr(s.Local.Addr))
	}
	return li
}

// Match reports whether a LISTEN socket covers ep. An IPv6 wildcard listener is treated as
// dual-stack; an IPv4 wildcard covers IPv4 only.
func (li *ListenIndex) Match(proto model.Proto, ep model.Endpoint, now time.Time, maxAge time.Duration) bool {
	if li == nil || (maxAge > 0 && now.Sub(li.at) > maxAge) {
		return false
	}
	a := model.NormalizeAddr(ep.Addr)
	for _, l := range li.addrs[listenKey{proto, ep.Port}] {
		switch {
		case l == a:
			return true
		case l.IsUnspecified() && l.Is6():
			return true
		case l.IsUnspecified() && l.Is4() && a.Is4():
			return true
		}
	}
	return false
}
