package sockdiag

import (
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"

	"github.com/lavr/ip-connection-explorer/internal/flows"
	"github.com/lavr/ip-connection-explorer/internal/model"
)

func convertSocket(proto model.Proto, s *netlink.Socket) flows.Socket {
	return flows.Socket{
		Proto:  proto,
		Local:  model.Endpoint{Addr: addr(s.ID.Source), Port: s.ID.SourcePort},
		Remote: model.Endpoint{Addr: addr(s.ID.Destination), Port: s.ID.DestinationPort},
		State:  model.SockState(s.State),
		Inode:  s.INode,
	}
}

func addr(ip net.IP) netip.Addr {
	a, _ := netip.AddrFromSlice(ip)
	return model.NormalizeAddr(a)
}
