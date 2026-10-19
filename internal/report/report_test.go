package report

import (
	"bytes"
	"encoding/csv"
	"flag"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lavr/ip-connection-explorer/internal/checkpoint"
	"github.com/lavr/ip-connection-explorer/internal/model"
)

var update = flag.Bool("update", false, "rewrite golden files")

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func ep(s string) model.Endpoint {
	ap := netip.MustParseAddrPort(s)
	return model.Endpoint{Addr: ap.Addr(), Port: ap.Port()}
}

var obs = model.ObserverRef{Hostname: "h1", MachineID: "m1", RunID: "r1"}

func base(key model.DepKey, dir model.Direction, conf model.Confidence, ev ...model.Evidence) model.Dependency {
	return model.Dependency{Key: key, Observer: obs, Direction: dir, FirstSeen: t0, LastSeen: t0.Add(time.Hour),
		FlowsObserved: 2, EverReplySeen: true, Confidence: conf, Evidence: ev, Sources: []model.Source{model.SourceEvent}}
}

func sampleInput() *Input {
	tcp := base(model.DepKey{Scope: "global", Family: 4, Proto: model.ProtoTCP, Status: model.RoleKnown,
		Initiator: netip.MustParseAddr("192.0.2.10"), Service: netip.MustParseAddr("198.51.100.5"), ServicePort: 443},
		model.DirOutbound, model.ConfidenceHigh, model.EvidenceConntrackNew)
	tcp.Processes = []model.ProcessRef{{Comm: "curl,x", Endpoint: model.Endpoint{Addr: netip.MustParseAddr("192.0.2.10")}, Count: 2}}
	udp := base(model.DepKey{Scope: "global", Family: 4, Proto: model.ProtoUDP, Status: model.RoleUnknown,
		A: ep("198.51.100.7:40000"), B: ep("192.0.2.10:5353")}, model.DirInbound, model.ConfidenceLow, model.EvidenceNone)
	icmp := base(model.DepKey{Scope: "global", Family: 4, Proto: model.ProtoICMP, Status: model.RoleKnown,
		Initiator: netip.MustParseAddr("192.0.2.10"), Service: netip.MustParseAddr("198.51.100.1"), ICMPType: 8},
		model.DirOutbound, model.ConfidenceMedium, model.EvidenceConntrackOriginal)
	lo := base(model.DepKey{Scope: "observer:m1", Family: 4, Proto: model.ProtoTCP, Status: model.RoleKnown,
		Initiator: netip.MustParseAddr("127.0.0.1"), Service: netip.MustParseAddr("127.0.0.1"), ServicePort: 5432},
		model.DirLocal, model.ConfidenceHigh, model.EvidenceListen)
	fwd := base(model.DepKey{Scope: "global", Family: 4, Proto: model.ProtoTCP, Status: model.RoleKnown,
		Initiator: netip.MustParseAddr("198.51.100.1"), Service: netip.MustParseAddr("203.0.113.5"), ServicePort: 80},
		model.DirForwarded, model.ConfidenceMedium, model.EvidenceConntrackOriginal)
	return &Input{
		Runs:         []checkpoint.File{{Run: checkpoint.Run{RunID: "r1"}, Host: checkpoint.Host{MachineID: "m1"}}},
		Dependencies: []model.Dependency{tcp, udp, icmp, lo, fwd},
	}
}

func render(t *testing.T, in *Input, opt Options) (string, string) {
	t.Helper()
	var out, sum bytes.Buffer
	if err := Write(&out, &sum, in, opt); err != nil {
		t.Fatal(err)
	}
	return out.String(), sum.String()
}

func TestCSVGolden(t *testing.T) {
	got, _ := render(t, sampleInput(), Options{Format: "csv", Role: "all"})
	golden := "testdata/small.csv"
	if *update {
		os.WriteFile(golden, []byte(got), 0o644)
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func rows(t *testing.T, s string) [][]string {
	t.Helper()
	r, err := csv.NewReader(strings.NewReader(s)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestCSVHeader(t *testing.T) {
	got, _ := render(t, sampleInput(), Options{Format: "csv", Role: "all"})
	want := "role_status,scope,proto,initiator,service,service_port,icmp_type,icmp_code,endpoint_a,port_a,endpoint_b,port_b,observer,run_id,direction,confidence,evidence,processes,first_seen,last_seen,flows_observed,flows_estimated,ever_reply_seen,coverage_status"
	if strings.Join(rows(t, got)[0], ",") != want {
		t.Fatalf("%v", rows(t, got)[0])
	}
}

func TestHiddenByDefault(t *testing.T) {
	got, sum := render(t, sampleInput(), Options{Format: "csv", Role: "all"})
	if n := len(rows(t, got)) - 1; n != 3 {
		t.Fatalf("rows=%d", n)
	}
	if !strings.Contains(sum, "hidden: 2 (loopback 1, forwarded 1, unresolved 0)") {
		t.Fatalf("summary %q", sum)
	}
	got, _ = render(t, sampleInput(), Options{Format: "csv", Role: "all", IncludeHidden: true})
	if n := len(rows(t, got)) - 1; n != 5 {
		t.Fatalf("rows=%d", n)
	}
}

func TestRoleFilter(t *testing.T) {
	got, _ := render(t, sampleInput(), Options{Format: "csv", Role: "unknown"})
	r := rows(t, got)
	if len(r) != 2 || r[1][0] != "unknown" {
		t.Fatalf("%v", r)
	}
}

func TestMinConfidence(t *testing.T) {
	got, _ := render(t, sampleInput(), Options{Format: "csv", Role: "all", MinConfidence: model.ConfidenceHigh})
	if n := len(rows(t, got)) - 1; n != 1 {
		t.Fatalf("rows=%d", n)
	}
}

func TestCoverageStatus(t *testing.T) {
	in := sampleInput()
	in.Runs[0].Coverage.HistoryIncomplete = true
	got, sum := render(t, in, Options{Format: "csv", Role: "known"})
	if r := rows(t, got); r[1][23] != "incomplete" {
		t.Fatalf("%v", r[1])
	}
	if !strings.Contains(sum, "incomplete runs: 1") {
		t.Fatalf("%q", sum)
	}
	in.Runs[0].Limits.Truncated = true
	got, _ = render(t, in, Options{Format: "csv", Role: "known"})
	if r := rows(t, got); r[1][23] != "truncated" {
		t.Fatalf("%v", r[1])
	}
}

func TestReportEmpty(t *testing.T) {
	got, sum := render(t, &Input{}, Options{Format: "csv", Role: "all"})
	if len(rows(t, got)) != 1 || !strings.Contains(sum, "rows: 0") {
		t.Fatalf("%q %q", got, sum)
	}
}

func TestJSONFormat(t *testing.T) {
	got, _ := render(t, sampleInput(), Options{Format: "json", Role: "all"})
	if !strings.Contains(got, `"dependencies"`) || strings.Contains(got, "127.0.0.1") {
		t.Fatalf("%s", got)
	}
}
