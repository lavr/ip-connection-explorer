//go:build linux

package sockdiag

import (
	"net"
	"testing"
	"time"

	"github.com/lavr/ip-connection-explorer/internal/model"
)

func TestSnapshotSeesListener(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	snap, err := Snapshot(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range snap.Sockets {
		if s.Proto == model.ProtoTCP && s.State == model.SockListen && s.Local.Port == port && s.Inode != 0 {
			return
		}
	}
	t.Fatalf("listener on %d not found among %d sockets", port, len(snap.Sockets))
}
