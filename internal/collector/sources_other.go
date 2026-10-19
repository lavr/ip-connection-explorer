//go:build !linux

package collector

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/lavr/ip-connection-explorer/internal/conntrack"
	"github.com/lavr/ip-connection-explorer/internal/flows"
	"github.com/lavr/ip-connection-explorer/internal/hostinfo"
	"github.com/lavr/ip-connection-explorer/internal/procindex"
)

var errUnsupported = errors.New("unsupported platform: collect requires Linux")

func LinuxSources(procRoot, etcRoot string) Sources {
	return Sources{
		Subscribe: func(uint64) (Subscription, error) { return nil, errUnsupported },
		Dump: func(context.Context, uint64, uint64, bool) (flows.DumpResult, conntrack.DumpStats, error) {
			return flows.DumpResult{}, conntrack.DumpStats{}, errUnsupported
		},
		Sockets: func(time.Time) (flows.SockSnapshot, error) { return flows.SockSnapshot{}, errUnsupported },
		Procs: func(time.Time) (flows.ProcIndex, procindex.Stats, error) {
			return flows.ProcIndex{}, procindex.Stats{}, errUnsupported
		},
		Host:         func() (hostinfo.Info, error) { return hostinfo.Info{}, errUnsupported },
		Addresses:    func() ([]netip.Addr, error) { return nil, errUnsupported },
		EventsSysctl: func() (int, error) { return 0, errUnsupported },
	}
}
