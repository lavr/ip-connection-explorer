package flows

import (
	"net/netip"
	"time"

	"github.com/lavr/ip-connection-explorer/internal/model"
)

type CTFlow struct {
	ID          uint32
	Orig, Reply model.Tuple
	TCPState    model.CTState
	HasTCPState bool
	Assured     bool
	SeenReply   bool
}

type Socket struct {
	Proto         model.Proto
	Local, Remote model.Endpoint
	State         model.SockState
	Inode         uint32
}

type HostContext struct {
	MachineID     string
	Hostname      string
	PortRangeLow  uint16
	PortRangeHigh uint16
	ListenMaxAge  time.Duration
}

func (h HostContext) ephemeral(port uint16) bool {
	return h.PortRangeLow > 0 && port >= h.PortRangeLow && port <= h.PortRangeHigh
}

type AddrSet interface {
	Has(netip.Addr) bool
}

type FlowEvidence struct {
	SawNew              bool
	NewState            model.CTState
	SawSimultaneousOpen bool
	Sources             map[model.Source]bool
}

type Inference struct {
	Status     model.RoleStatus
	Initiator  model.Endpoint
	Service    model.Endpoint
	Evidence   []model.Evidence
	Confidence model.Confidence
}
