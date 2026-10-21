//go:build linux

package conntrack

import (
	ct "github.com/ti-mo/conntrack"

	"github.com/lavr/ip-connection-explorer/internal/flows"
	"github.com/lavr/ip-connection-explorer/internal/model"
)

func Convert(f ct.Flow) flows.CTFlow {
	c := flows.CTFlow{
		ID:        f.ID,
		Orig:      tuple(f.TupleOrig, f.Zone),
		Reply:     tuple(f.TupleReply, f.Zone),
		Assured:   f.Status.Assured(),
		SeenReply: f.Status.SeenReply(),
		SrcNAT:    f.Status.SrcNAT(),
		DstNAT:    f.Status.DstNAT(),
	}
	if f.ProtoInfo.TCP != nil {
		c.TCPState, c.HasTCPState = model.CTState(f.ProtoInfo.TCP.State), true
	}
	return c
}

func tuple(t ct.Tuple, zone uint16) model.Tuple {
	return model.Tuple{
		Src:      model.Endpoint{Addr: model.NormalizeAddr(t.IP.SourceAddress), Port: t.Proto.SourcePort},
		Dst:      model.Endpoint{Addr: model.NormalizeAddr(t.IP.DestinationAddress), Port: t.Proto.DestinationPort},
		Proto:    model.Proto(t.Proto.Protocol),
		ICMPType: t.Proto.ICMPType,
		ICMPCode: t.Proto.ICMPCode,
		Zone:     zone,
	}
}
