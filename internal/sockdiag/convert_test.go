package sockdiag

import (
	"net"
	"net/netip"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/lavr/ip-connection-explorer/internal/model"
)

func TestConvertSocketMapsState(t *testing.T) {
	s := &netlink.Socket{State: 10, INode: 77}
	s.ID.Source = net.ParseIP("::ffff:192.0.2.10")
	s.ID.SourcePort = 5432
	s.ID.Destination = net.IPv4zero
	got := convertSocket(model.ProtoTCP, s)
	if got.State != model.SockListen || got.Inode != 77 || got.Local.Addr != netip.MustParseAddr("192.0.2.10") || got.Local.Port != 5432 || got.Proto != model.ProtoTCP {
		t.Fatalf("%+v", got)
	}
}

func TestConvertSocketIPv6(t *testing.T) {
	s := &netlink.Socket{State: 1}
	s.ID.Source = net.ParseIP("2001:db8::10")
	s.ID.Destination = net.ParseIP("2001:db8::20")
	s.ID.DestinationPort = 443
	got := convertSocket(model.ProtoTCP, s)
	if got.Remote.Addr != netip.MustParseAddr("2001:db8::20") || got.Remote.Port != 443 || got.State != model.SockEstablished {
		t.Fatalf("%+v", got)
	}
}
