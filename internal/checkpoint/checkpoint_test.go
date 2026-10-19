package checkpoint

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lavr/ip-connection-explorer/internal/flows"
	"github.com/lavr/ip-connection-explorer/internal/model"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func sample(gen uint64) *File {
	return &File{
		SchemaVersion: SchemaVersion,
		Tool:          Tool{Version: "v0.0.0", Commit: "abc"},
		Host: Host{Hostname: "h1", MachineID: "m1", BootID: "b1", Kernel: "6.8.0",
			Addresses: []flows.AddrSeen{{Addr: netip.MustParseAddr("192.0.2.10"), FirstSeen: t0, LastSeen: t0}}},
		Run:      Run{RunID: "r1", StartedAt: t0, CheckpointAt: t0.Add(time.Minute), Generation: gen, Params: map[string]string{"duration": "7d"}},
		Coverage: model.Coverage{NetNS: "current", EventsSysctl: 1, Intervals: []model.Interval{{From: t0}}, Counters: map[string]uint64{"x": 1}},
		Limits:   model.LimitsState{MaxActive: 10},
		Dependencies: []model.Dependency{{
			Key:      model.DepKey{Scope: "global", Family: 4, Proto: model.ProtoTCP, Status: model.RoleKnown, Initiator: netip.MustParseAddr("192.0.2.10"), Service: netip.MustParseAddr("198.51.100.5"), ServicePort: 443},
			Observer: model.ObserverRef{Hostname: "h1", MachineID: "m1", RunID: "r1"},
			Sources:  []model.Source{model.SourceEvent}, Evidence: []model.Evidence{model.EvidenceConntrackNew},
			FirstSeen: t0, LastSeen: t0, FlowsObserved: 1, Confidence: model.ConfidenceHigh, Direction: model.DirOutbound,
		}},
	}
}

func TestRoundtrip(t *testing.T) {
	dir := t.TempDir()
	f := sample(1)
	p, err := Write(dir, f)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(p) != "h1-r1.json.gz" {
		t.Fatalf("path %s", p)
	}
	back, err := Read(p)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f, back) {
		t.Fatalf("mismatch\n%+v\n%+v", f, back)
	}
}

func TestRejectsOtherSchema(t *testing.T) {
	dir := t.TempDir()
	f := sample(1)
	f.SchemaVersion = 2
	p, err := Write(dir, f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Read(p); err == nil {
		t.Fatal("schema 2 accepted")
	}
}

type failSyncFS struct{ osFS }

func (failSyncFS) Sync(*os.File) error { return errors.New("injected sync failure") }

func TestWriteFailureKeepsPrevious(t *testing.T) {
	dir := t.TempDir()
	p, err := Write(dir, sample(1))
	if err != nil {
		t.Fatal(err)
	}
	fsys = failSyncFS{}
	defer func() { fsys = osFS{} }()
	if _, err := Write(dir, sample(2)); err == nil {
		t.Fatal("expected error")
	}
	back, err := Read(p)
	if err != nil || back.Run.Generation != 1 {
		t.Fatalf("previous lost: %v %+v", err, back)
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("temp file left: %s", e.Name())
		}
	}
}

func TestLockExclusive(t *testing.T) {
	dir := t.TempDir()
	release, err := Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Lock(dir); !errors.Is(err, ErrLocked) {
		t.Fatalf("second lock: %v", err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	r2, err := Lock(dir)
	if err != nil {
		t.Fatalf("relock: %v", err)
	}
	_ = r2()
}

func TestFileNameSanitized(t *testing.T) {
	if got := FileName("a b/c", "r1"); got != "a_b_c-r1.json.gz" {
		t.Fatal(got)
	}
}

func TestNewRunIDUnique(t *testing.T) {
	a, b := NewRunID(), NewRunID()
	if a == b || len(a) != len("20060102T150405Z-abcdef") {
		t.Fatalf("%s %s", a, b)
	}
}

func TestWriteToPath(t *testing.T) {
	p := filepath.Join(t.TempDir(), "out.json.gz")
	if err := WriteTo(p, sample(3)); err != nil {
		t.Fatal(err)
	}
	if f, err := Read(p); err != nil || f.Run.Generation != 3 {
		t.Fatalf("%v %+v", err, f)
	}
}
