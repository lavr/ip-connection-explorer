package merge

import (
	"flag"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/lavr/ip-connection-explorer/internal/checkpoint"
	"github.com/lavr/ip-connection-explorer/internal/model"
)

var update = flag.Bool("update", false, "regenerate testdata fixtures")

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func ep(s string) model.Endpoint {
	ap := netip.MustParseAddrPort(s)
	return model.Endpoint{Addr: ap.Addr(), Port: ap.Port()}
}

func known(machine, run string, dir model.Direction, init, svc string, port uint16, orig model.Tuple) model.Dependency {
	return model.Dependency{
		Key: model.DepKey{Scope: "global", Family: 4, Proto: model.ProtoTCP, Status: model.RoleKnown,
			Initiator: netip.MustParseAddr(init), Service: netip.MustParseAddr(svc), ServicePort: port},
		Observer:  model.ObserverRef{Hostname: "host-" + machine, MachineID: machine, RunID: run},
		Direction: dir, FirstSeen: t0, LastSeen: t0, FlowsObserved: 1,
		Sources: []model.Source{model.SourceEvent}, Evidence: []model.Evidence{model.EvidenceConntrackNew},
		Confidence: model.ConfidenceHigh,
		Examples:   []model.Example{{At: t0, Orig: orig, Reply: model.Tuple{Src: orig.Dst, Dst: orig.Src, Proto: orig.Proto}}},
	}
}

func file(machine, run string, gen uint64, deps ...model.Dependency) *checkpoint.File {
	return &checkpoint.File{
		SchemaVersion: checkpoint.SchemaVersion,
		Host:          checkpoint.Host{Hostname: "host-" + machine, MachineID: machine, BootID: "boot-" + machine},
		Run:           checkpoint.Run{RunID: run, StartedAt: t0, CheckpointAt: t0, Generation: gen},
		Coverage:      model.Coverage{NetNS: "current", Counters: map[string]uint64{}},
		Dependencies:  deps,
	}
}

var origAB = model.Tuple{Src: ep("192.0.2.10:40000"), Dst: ep("198.51.100.5:443"), Proto: model.ProtoTCP}

func fixtureA() *checkpoint.File {
	return file("ma", "ra", 3, known("ma", "ra", model.DirOutbound, "192.0.2.10", "198.51.100.5", 443, origAB))
}

func fixtureB() *checkpoint.File {
	return file("mb", "rb", 2, known("mb", "rb", model.DirInbound, "192.0.2.10", "198.51.100.5", 443, origAB))
}

func TestGenerateFixtures(t *testing.T) {
	if !*update {
		t.Skip("run with -update to regenerate")
	}
	for name, f := range map[string]*checkpoint.File{"a.json.gz": fixtureA(), "b.json.gz": fixtureB()} {
		if err := checkpoint.WriteTo(filepath.Join("..", "..", "testdata", name), f); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHighestGenerationWins(t *testing.T) {
	old := file("ma", "ra", 1)
	m, err := Merge([]*checkpoint.File{old, fixtureA()})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Runs) != 1 || m.Runs[0].Run.Generation != 3 || len(m.Dependencies) != 1 || m.Kind != "merged" {
		t.Fatalf("%+v", m)
	}
}

func TestSameGenerationDifferentContentErrors(t *testing.T) {
	a := fixtureA()
	b := fixtureA()
	b.Dependencies[0].FlowsObserved = 9
	if _, err := Merge([]*checkpoint.File{a, b}); err == nil {
		t.Fatal("expected error")
	}
	if _, err := Merge([]*checkpoint.File{fixtureA(), fixtureA()}); err != nil {
		t.Fatalf("identical duplicate rejected: %v", err)
	}
}

func TestMismatchedBootErrors(t *testing.T) {
	a := fixtureA()
	b := file("ma", "ra", 4)
	b.Host.BootID = "other"
	if _, err := Merge([]*checkpoint.File{a, b}); err == nil {
		t.Fatal("expected error")
	}
}

func TestCountersNotSummed(t *testing.T) {
	m, err := Merge([]*checkpoint.File{fixtureA(), fixtureB()})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Dependencies) != 2 {
		t.Fatalf("%d", len(m.Dependencies))
	}
	dirs := map[string]model.Direction{}
	for _, d := range m.Dependencies {
		if d.FlowsObserved != 1 {
			t.Fatalf("summed: %d", d.FlowsObserved)
		}
		dirs[d.Observer.MachineID] = d.Direction
	}
	if dirs["ma"] != model.DirOutbound || dirs["mb"] != model.DirInbound || len(m.Conflicts) != 0 {
		t.Fatalf("%v %v", dirs, m.Conflicts)
	}
}

func TestLocalhostKeptSeparate(t *testing.T) {
	lo := model.Tuple{Src: ep("127.0.0.1:40000"), Dst: ep("127.0.0.1:5432"), Proto: model.ProtoTCP}
	da := known("ma", "ra", model.DirLocal, "127.0.0.1", "127.0.0.1", 5432, lo)
	da.Key.Scope = "observer:ma"
	db := known("mb", "rb", model.DirLocal, "127.0.0.1", "127.0.0.1", 5432, lo)
	db.Key.Scope = "observer:mb"
	m, err := Merge([]*checkpoint.File{file("ma", "ra", 1, da), file("mb", "rb", 1, db)})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Dependencies) != 2 || m.Dependencies[0].Key == m.Dependencies[1].Key || len(m.Conflicts) != 0 {
		t.Fatalf("%+v", m)
	}
}

func TestConflictOnSameTransport(t *testing.T) {
	wrong := known("mb", "rb", model.DirOutbound, "198.51.100.5", "192.0.2.10", 40000, origAB)
	m, err := Merge([]*checkpoint.File{fixtureA(), file("mb", "rb", 1, wrong)})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Conflicts) != 1 || len(m.Conflicts[0].Observers) != 2 {
		t.Fatalf("%+v", m.Conflicts)
	}
}
