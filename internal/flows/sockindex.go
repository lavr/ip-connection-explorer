package flows

import (
	"net/netip"

	"github.com/lavr/ip-connection-explorer/internal/model"
)

type connKey struct {
	proto         model.Proto
	local, remote model.Endpoint
}

type portKey struct {
	proto model.Proto
	port  uint16
}

// socketIndex finds the sockets of a flow without scanning the whole snapshot. Connected
// sockets are keyed by the full tuple, because thousands of them can share one local
// VIP:port; unconnected UDP sockets are keyed by local port. The matching rules are the
// same as socketMatches.
type socketIndex struct {
	conn     map[connKey][]Socket
	unbound  map[portKey][]Socket
	wildcard [2]netip.Addr
}

func newSocketIndex(socks []Socket) *socketIndex {
	si := &socketIndex{
		conn:     map[connKey][]Socket{},
		unbound:  map[portKey][]Socket{},
		wildcard: [2]netip.Addr{netip.IPv4Unspecified(), netip.IPv6Unspecified()},
	}
	for _, s := range socks {
		remote := normEP(s.Remote)
		connected := remote.Addr.IsValid() && !remote.Addr.IsUnspecified()
		switch {
		case s.Proto == model.ProtoTCP && s.State == model.SockListen:
		case s.Proto == model.ProtoTCP || connected:
			k := connKey{s.Proto, normEP(s.Local), remote}
			si.conn[k] = append(si.conn[k], s)
		case s.Proto == model.ProtoUDP:
			k := portKey{s.Proto, s.Local.Port}
			si.unbound[k] = append(si.unbound[k], s)
		}
	}
	return si
}

// each calls fn for every socket owning the local side of a flow and returns how many
// candidates it looked at.
func (si *socketIndex) each(proto model.Proto, local, remote model.Endpoint, fn func(Socket)) int {
	if si == nil {
		return 0
	}
	local, remote = normEP(local), normEP(remote)
	probes := 0
	visit := func(cands []Socket) {
		for _, s := range cands {
			probes++
			if socketMatches(s, local, remote) {
				fn(s)
			}
		}
	}
	visit(si.conn[connKey{proto, local, remote}])
	for _, w := range si.wildcard {
		if w != local.Addr {
			visit(si.conn[connKey{proto, model.Endpoint{Addr: w, Port: local.Port}, remote}])
		}
	}
	if proto == model.ProtoUDP {
		visit(si.unbound[portKey{proto, local.Port}])
	}
	return probes
}
