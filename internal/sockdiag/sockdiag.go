//go:build linux

package sockdiag

import (
	"errors"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/lavr/ip-connection-explorer/internal/flows"
	"github.com/lavr/ip-connection-explorer/internal/model"
)

// Snapshot lists TCP (all states) and UDP sockets of the current network namespace.
// An interrupted dump keeps the partial result and is marked incomplete.
func Snapshot(now time.Time) (flows.SockSnapshot, error) {
	snap := flows.SockSnapshot{At: now, Complete: true}
	type query struct {
		proto model.Proto
		fn    func(uint8) ([]*netlink.Socket, error)
	}
	for _, q := range []query{{model.ProtoTCP, netlink.SocketDiagTCP}, {model.ProtoUDP, netlink.SocketDiagUDP}} {
		for _, fam := range []uint8{unix.AF_INET, unix.AF_INET6} {
			socks, err := q.fn(fam)
			if err != nil && !errors.Is(err, netlink.ErrDumpInterrupted) {
				return snap, err
			}
			if err != nil {
				snap.Complete = false
			}
			for _, s := range socks {
				snap.Sockets = append(snap.Sockets, convertSocket(q.proto, s))
			}
		}
	}
	return snap, nil
}
