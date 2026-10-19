//go:build linux

package collector

import (
	"time"

	ct "github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"

	"github.com/lavr/ip-connection-explorer/internal/conntrack"
	"github.com/lavr/ip-connection-explorer/internal/flows"
	"github.com/lavr/ip-connection-explorer/internal/hostinfo"
	"github.com/lavr/ip-connection-explorer/internal/procindex"
	"github.com/lavr/ip-connection-explorer/internal/sockdiag"
)

const readBuffer = 8 << 20

func LinuxSources(procRoot, etcRoot string) Sources {
	sub := &conntrack.Subscriber{
		Dial:       func() (conntrack.RawListener, error) { return ct.Dial(nil) },
		ReadBuffer: readBuffer,
		Now:        now,
	}
	dumper := &conntrack.Dumper{
		Dial: func() (conntrack.QueryConn, error) { return netfilter.Dial(nil) },
		Now:  now,
	}
	return Sources{
		Kernel: func() (int, error) {
			release, err := hostinfo.KernelRelease(procRoot)
			if err != nil {
				return 0, err
			}
			return conntrack.KernelReady(procRoot, "/sys", "/lib/modules/"+release)
		},
		Subscribe: func(epoch uint64) (Subscription, error) {
			s, err := sub.Subscribe(epoch)
			if err != nil {
				return nil, err
			}
			return s, nil
		},
		Dump:    dumper.Dump,
		Sockets: sockdiag.Snapshot,
		Procs: func(at time.Time) (flows.ProcIndex, procindex.Stats, error) {
			return procindex.Build(procRoot, at)
		},
		Host:         func() (hostinfo.Info, error) { return hostinfo.Collect(procRoot, etcRoot) },
		Addresses:    hostinfo.Addresses,
		EventsSysctl: func() (int, error) { return conntrack.EventsSysctl(procRoot) },
	}
}
