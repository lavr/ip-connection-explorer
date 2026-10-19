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
	udp   map[uint16][]netip.Addr
}

func NewListenIndex(socks []Socket, at time.Time) *ListenIndex {
	li := &ListenIndex{at: at, addrs: map[listenKey][]netip.Addr{}, udp: map[uint16][]netip.Addr{}}
	for _, s := range socks {
		if s.Proto == model.ProtoUDP && (!s.Remote.Addr.IsValid() || s.Remote.Addr.IsUnspecified()) {
			li.udp[s.Local.Port] = append(li.udp[s.Local.Port], model.NormalizeAddr(s.Local.Addr))
			continue
		}
		if s.Proto != model.ProtoTCP || s.State != model.SockListen {
			continue
		}
		k := listenKey{s.Proto, s.Local.Port}
		li.addrs[k] = append(li.addrs[k], model.NormalizeAddr(s.Local.Addr))
	}
	return li
}

type MatchKind uint8

const (
	MatchNone MatchKind = iota
	// MatchAssumed: an IPv4 endpoint covered only by an IPv6 wildcard listener. Whether that
	// socket is dual-stack (IPV6_V6ONLY unset) is not known from the snapshot.
	MatchAssumed
	MatchExact
)

// UDPBound reports whether an unconnected UDP socket is bound to ep.
func (li *ListenIndex) UDPBound(ep model.Endpoint, now time.Time, maxAge time.Duration) bool {
	if li == nil || (maxAge > 0 && now.Sub(li.at) > maxAge) {
		return false
	}
	a := model.NormalizeAddr(ep.Addr)
	for _, l := range li.udp[ep.Port] {
		if l == a || l.IsUnspecified() {
			return true
		}
	}
	return false
}

// Match reports whether a LISTEN socket covers ep.
func (li *ListenIndex) Match(proto model.Proto, ep model.Endpoint, now time.Time, maxAge time.Duration) MatchKind {
	if li == nil || (maxAge > 0 && now.Sub(li.at) > maxAge) {
		return MatchNone
	}
	a := model.NormalizeAddr(ep.Addr)
	best := MatchNone
	for _, l := range li.addrs[listenKey{proto, ep.Port}] {
		switch {
		case l == a, l.IsUnspecified() && l.Is4() && a.Is4(), l.IsUnspecified() && l.Is6() && a.Is6():
			return MatchExact
		case l.IsUnspecified() && l.Is6() && a.Is4():
			best = MatchAssumed
		}
	}
	return best
}
