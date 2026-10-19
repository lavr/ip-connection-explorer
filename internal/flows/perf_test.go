package flows

import (
	"fmt"
	"math/rand"
	"net/netip"
	"slices"
	"sort"
	"testing"

	"github.com/lavr/ip-connection-explorer/internal/model"
)

// vipFixture: 10k established TCP sockets on one VIP:443 plus some UDP, each with an owner.
func vipFixture(n int) (SockSnapshot, ProcIndex, []CTFlow) {
	snap := SockSnapshot{At: at(0), Complete: true}
	idx := ProcIndex{At: at(0), ByInode: map[uint32][]Proc{}}
	var fl []CTFlow
	snap.Sockets = append(snap.Sockets, listen(model.ProtoTCP, "0.0.0.0:443"))
	for i := 0; i < n; i++ {
		remote := model.Endpoint{Addr: netip.AddrFrom4([4]byte{198, 51, byte(100 + i/50000), byte(i / 250 % 200)}), Port: uint16(1024 + i%60000)}
		ino := uint32(1000 + i)
		snap.Sockets = append(snap.Sockets, Socket{Proto: model.ProtoTCP, Local: ep("192.0.2.10:443"), Remote: remote, State: model.SockEstablished, Inode: ino})
		idx.ByInode[ino] = []Proc{{PID: 100 + i%8, Comm: fmt.Sprintf("nginx%d", i%8)}}
		o := model.Tuple{Src: remote, Dst: ep("192.0.2.10:443"), Proto: model.ProtoTCP}
		fl = append(fl, CTFlow{ID: uint32(i + 1), Orig: o, Reply: model.Tuple{Src: o.Dst, Dst: o.Src, Proto: model.ProtoTCP}})
	}
	return snap, idx, fl
}

func TestAttributionDoesNotScanAllSockets(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, Limits{MaxProcesses: 5, MaxExamples: 3})
	m.SetEpoch(1)
	snap, idx, fl := vipFixture(10000)
	m.ApplySockets(snap)
	m.ApplyProcIndex(idx)
	m.attrProbes = 0
	for i := 0; i < 100; i++ {
		m.ApplyEvent(CTEvent{Kind: EventUpdate, At: at(1), Epoch: 1, Flow: fl[i]})
	}
	if m.attrProbes > 100*4 {
		t.Fatalf("probes per event = %d", m.attrProbes/100)
	}
}

func TestSetAddressesUnchangedIsCheap(t *testing.T) {
	m := newTestMachine(t, "m1", []string{"192.0.2.10"}, Limits{MaxProcesses: 5, MaxExamples: 3})
	m.SetEpoch(1)
	snap, idx, fl := vipFixture(2000)
	m.ApplySockets(snap)
	m.ApplyProcIndex(idx)
	for _, f := range fl {
		m.ApplyEvent(CTEvent{Kind: EventUpdate, At: at(1), Epoch: 1, Flow: f})
	}
	m.reclassifications = 0
	m.SetAddresses([]netip.Addr{netip.MustParseAddr("192.0.2.10")}, at(2))
	if m.reclassifications != 0 {
		t.Fatalf("unchanged addresses reclassified %d flows", m.reclassifications)
	}
	if as := m.Snapshot().Addresses; !as[0].LastSeen.Equal(at(2)) {
		t.Fatalf("last seen not updated: %+v", as)
	}
	m.SetAddresses([]netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.11")}, at(3))
	if m.reclassifications == 0 {
		t.Fatal("new address did not trigger reclassification")
	}
}

// bruteOwners is the reference attribution: a full scan with the original matching rules.
func bruteOwners(socks []Socket, idx ProcIndex, proto model.Proto, local, remote model.Endpoint) []string {
	var out []string
	for _, s := range socks {
		if s.Proto != proto || !socketMatches(s, local, remote) {
			continue
		}
		for _, p := range idx.ByInode[s.Inode] {
			out = append(out, p.Comm)
		}
	}
	sort.Strings(out)
	return slices.Compact(out)
}

func TestIndexedAttributionMatchesBruteForce(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	addrs := []string{"192.0.2.10", "192.0.2.11", "2001:db8::10", "0.0.0.0", "::"}
	remotes := []string{"198.51.100.1", "198.51.100.2", "2001:db8::99"}
	pick := func(xs []string) netip.Addr { return netip.MustParseAddr(xs[r.Intn(len(xs))]) }
	var socks []Socket
	idx := ProcIndex{At: at(0), ByInode: map[uint32][]Proc{}}
	for i := 0; i < 3000; i++ {
		proto := []model.Proto{model.ProtoTCP, model.ProtoUDP}[r.Intn(2)]
		s := Socket{Proto: proto, Local: model.Endpoint{Addr: pick(addrs), Port: uint16(1 + r.Intn(20))}, Inode: uint32(i + 1)}
		if r.Intn(3) > 0 {
			s.Remote = model.Endpoint{Addr: pick(remotes), Port: uint16(1 + r.Intn(20))}
			s.State = model.SockEstablished
		} else if proto == model.ProtoTCP {
			s.State = model.SockListen
		}
		socks = append(socks, s)
		idx.ByInode[s.Inode] = []Proc{{PID: i, Comm: fmt.Sprintf("p%d", r.Intn(40))}}
	}
	si := newSocketIndex(socks)
	for i := 0; i < 5000; i++ {
		proto := []model.Proto{model.ProtoTCP, model.ProtoUDP}[r.Intn(2)]
		local := model.Endpoint{Addr: pick(addrs[:3]), Port: uint16(1 + r.Intn(20))}
		remote := model.Endpoint{Addr: pick(remotes), Port: uint16(1 + r.Intn(20))}
		want := bruteOwners(socks, idx, proto, local, remote)
		var got []string
		si.each(proto, local, remote, func(s Socket) {
			for _, p := range idx.ByInode[s.Inode] {
				got = append(got, p.Comm)
			}
		})
		sort.Strings(got)
		got = slices.Compact(got)
		if !slices.Equal(got, want) {
			t.Fatalf("%v %v -> %v: got %v want %v", proto, local, remote, got, want)
		}
	}
}

func benchMachine(b *testing.B, n int) (*Machine, []CTFlow, SockSnapshot, ProcIndex) {
	b.Helper()
	m := NewMachine(host, model.ObserverRef{MachineID: "m1"}, Limits{MaxProcesses: 5, MaxExamples: 3}, 0, 0)
	m.SetAddresses([]netip.Addr{netip.MustParseAddr("192.0.2.10")}, t0)
	m.SetEpoch(1)
	snap, idx, fl := vipFixture(n)
	m.ApplySockets(snap)
	m.ApplyProcIndex(idx)
	for _, f := range fl {
		m.ApplyEvent(CTEvent{Kind: EventNew, At: at(1), Epoch: 1, Flow: f})
	}
	return m, fl, snap, idx
}

func BenchmarkApplyEventVIP10k(b *testing.B) {
	m, fl, _, _ := benchMachine(b, 10000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.ApplyEvent(CTEvent{Kind: EventUpdate, At: at(2), Epoch: 1, Flow: fl[i%len(fl)]})
	}
}

func BenchmarkApplySockets50k(b *testing.B) {
	m, _, snap, _ := benchMachine(b, 50000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.ApplySockets(snap)
	}
}

func BenchmarkApplyProcIndex50k(b *testing.B) {
	m, _, _, idx := benchMachine(b, 50000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.ApplyProcIndex(idx)
	}
}

func BenchmarkSnapshot50k(b *testing.B) {
	m, _, _, _ := benchMachine(b, 50000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.Snapshot()
	}
}
