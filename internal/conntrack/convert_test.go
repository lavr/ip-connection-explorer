//go:build linux

package conntrack

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	ct "github.com/ti-mo/conntrack"

	"github.com/lavr/ip-connection-explorer/internal/model"
)

func TestConvertNormalizesAndFlags(t *testing.T) {
	f := ct.NewFlow(6, ct.StatusAssured|ct.StatusSeenReply, netip.MustParseAddr("::ffff:192.0.2.1"), netip.MustParseAddr("198.51.100.5"), 40000, 443, 60, 0)
	f.ProtoInfo.TCP = &ct.ProtoInfoTCP{State: uint8(model.CTEstablished)}
	f.Zone = 7
	c := Convert(f)
	if c.Orig.Src.Addr != netip.MustParseAddr("192.0.2.1") || c.Orig.Proto != model.ProtoTCP || c.Reply.Src.Port != 443 {
		t.Fatalf("%+v", c)
	}
	if !c.Assured || !c.SeenReply || !c.HasTCPState || c.TCPState != model.CTEstablished || c.Orig.Zone != 7 || c.Reply.Zone != 7 {
		t.Fatalf("%+v", c)
	}
}

func TestConvertNATFlags(t *testing.T) {
	f := ct.NewFlow(6, ct.StatusSrcNAT|ct.StatusDstNATDone, netip.MustParseAddr("198.18.70.5"), netip.MustParseAddr("198.51.100.5"), 40000, 443, 60, 0)
	if c := Convert(f); !c.SrcNAT || c.DstNAT {
		t.Fatalf("%+v", c)
	}
	f.Status = ct.StatusDstNAT
	if c := Convert(f); c.SrcNAT || !c.DstNAT {
		t.Fatalf("%+v", c)
	}
}

func TestConvertICMP(t *testing.T) {
	f := ct.NewFlow(1, 0, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.5"), 0, 0, 30, 0)
	f.TupleOrig.Proto.ICMPv4, f.TupleOrig.Proto.ICMPType, f.TupleOrig.Proto.ICMPCode = true, 8, 0
	c := Convert(f)
	if c.Orig.Proto != model.ProtoICMP || c.Orig.ICMPType != 8 || c.HasTCPState {
		t.Fatalf("%+v", c)
	}
}

func TestEventsSysctl(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "sys/net/netfilter")
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p, "nf_conntrack_events"), []byte("2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if v, err := EventsSysctl(root); err != nil || v != 2 {
		t.Fatalf("%d %v", v, err)
	}
	if _, err := EventsSysctl(t.TempDir()); err == nil {
		t.Fatal("missing file accepted")
	}
}
