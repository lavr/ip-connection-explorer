package exporter

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lavr/ip-connection-explorer/internal/flows"
	"github.com/lavr/ip-connection-explorer/internal/model"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func at(sec int) time.Time { return t0.Add(time.Duration(sec) * time.Second) }

func lbl(dst string, port uint16) flows.Labels {
	return flows.Labels{Role: model.RoleKnown, Direction: model.DirOutbound, Proto: model.ProtoTCP,
		Src: netip.MustParseAddr("192.0.2.10"), Dst: netip.MustParseAddr(dst), DstPort: port}
}

func text(t *testing.T, tb *Table) string {
	t.Helper()
	var b bytes.Buffer
	if err := tb.WriteText(&b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func mustContain(t *testing.T, body string, lines ...string) {
	t.Helper()
	for _, l := range lines {
		if !strings.Contains(body, l+"\n") {
			t.Fatalf("missing %q in\n%s", l, body)
		}
	}
}

func mustNotContain(t *testing.T, body string, sub string) {
	t.Helper()
	if strings.Contains(body, sub) {
		t.Fatalf("unexpected %q in\n%s", sub, body)
	}
}

const pg = `role="known",direction="outbound",proto="tcp",src_ip="192.0.2.10",dst_ip="198.51.100.6",dst_port="5432"`

func TestFinishedCountsAndActiveIsSampled(t *testing.T) {
	tb := New(time.Hour, 10, BuildInfo{Version: "v", Commit: "c"})
	tb.Finished(lbl("198.51.100.6", 5432), at(1))
	tb.Finished(lbl("198.51.100.6", 5432), at(2))
	body := text(t, tb)
	mustContain(t, body, "ipcx_connections_finished_total{"+pg+"} 2", "ipcx_connections_active{"+pg+"} 0")
	tb.Refresh(map[flows.Labels]int{lbl("198.51.100.6", 5432): 3}, flows.Health{ActiveFlows: 3}, true, at(10))
	body = text(t, tb)
	mustContain(t, body, "ipcx_connections_finished_total{"+pg+"} 2", "ipcx_connections_active{"+pg+"} 3",
		"ipcx_flows_active 3", "ipcx_exporter_ready 1", "ipcx_exporter_series 1")
}

func TestTTLExpiresIdleSeriesOnly(t *testing.T) {
	tb := New(time.Minute, 10, BuildInfo{})
	tb.Finished(lbl("198.51.100.6", 5432), at(0))
	tb.Finished(lbl("198.51.100.7", 443), at(0))
	tb.Refresh(map[flows.Labels]int{lbl("198.51.100.7", 443): 1}, flows.Health{}, true, at(30))
	tb.Refresh(map[flows.Labels]int{lbl("198.51.100.7", 443): 1}, flows.Health{}, true, at(120))
	body := text(t, tb)
	mustNotContain(t, body, `dst_ip="198.51.100.6"`)
	mustContain(t, body, `ipcx_connections_finished_total{role="known",direction="outbound",proto="tcp",src_ip="192.0.2.10",dst_ip="198.51.100.7",dst_port="443"} 1`)
	tb.Refresh(map[flows.Labels]int{}, flows.Health{}, true, at(150))
	tb.Refresh(map[flows.Labels]int{}, flows.Health{}, true, at(200))
	if body := text(t, tb); strings.Contains(body, `dst_ip="198.51.100.7"`) {
		t.Fatalf("not expired:\n%s", body)
	}
	tb.Finished(lbl("198.51.100.6", 5432), at(300))
	mustContain(t, text(t, tb), "ipcx_connections_finished_total{"+pg+"} 1")
}

func TestMaxSeriesRejectsNewKeysButUpdatesExisting(t *testing.T) {
	tb := New(time.Hour, 2, BuildInfo{})
	tb.Finished(lbl("198.51.100.1", 1), at(0))
	tb.Finished(lbl("198.51.100.2", 2), at(0))
	tb.Finished(lbl("198.51.100.3", 3), at(0))
	tb.Finished(lbl("198.51.100.1", 1), at(1))
	body := text(t, tb)
	mustNotContain(t, body, `dst_ip="198.51.100.3"`)
	mustContain(t, body, "ipcx_exporter_series 2", "ipcx_exporter_series_rejected_total 1",
		`ipcx_connections_finished_total{role="known",direction="outbound",proto="tcp",src_ip="192.0.2.10",dst_ip="198.51.100.1",dst_port="1"} 2`)
}

func TestFullTableReclaimsExpiredOnAdmission(t *testing.T) {
	tb := New(time.Minute, 1, BuildInfo{})
	tb.Finished(lbl("198.51.100.1", 1), at(0))
	tb.Finished(lbl("198.51.100.2", 2), at(600))
	body := text(t, tb)
	mustNotContain(t, body, `dst_ip="198.51.100.1"`)
	mustContain(t, body, "ipcx_exporter_series_rejected_total 0")
}

func TestRefreshAdmitsActiveKeysInStableOrder(t *testing.T) {
	act := map[flows.Labels]int{}
	for i := range 20 {
		act[lbl(fmt.Sprintf("198.51.100.%d", i+1), 80)] = 1
	}
	var first string
	for i := range 5 {
		tb := New(time.Hour, 5, BuildInfo{})
		tb.Refresh(act, flows.Health{}, true, at(0))
		body := text(t, tb)
		if i == 0 {
			first = body
		} else if body != first {
			t.Fatalf("admission depends on map order:\n%s\n---\n%s", first, body)
		}
	}
	mustContain(t, first, "ipcx_exporter_series 5", "ipcx_exporter_series_rejected_total 15")
}

func TestHealthMetrics(t *testing.T) {
	tb := New(time.Hour, 10, BuildInfo{Version: `1.0"x`, Commit: "a\\b\nc"})
	body := text(t, tb)
	mustContain(t, body, "ipcx_exporter_ready 0", `ipcx_build_info{version="1.0\"x",commit="a\\b\nc"} 1`)
	mustNotContain(t, body, "ipcx_last_checkpoint_timestamp_seconds")
	tb.Refresh(nil, flows.Health{GapsOpened: 3, OpenGaps: []model.GapKind{model.GapMap}, ActiveRejected: 7}, true, at(5))
	tb.CheckpointWritten(at(7))
	body = text(t, tb)
	mustContain(t, body, "ipcx_gaps_total 3", `ipcx_gap_open{kind="map"} 1`, `ipcx_gap_open{kind="attribution"} 0`,
		"ipcx_flows_rejected_total 7",
		fmt.Sprintf("ipcx_exporter_active_snapshot_timestamp_seconds %d", at(5).Unix()),
		fmt.Sprintf("ipcx_last_checkpoint_timestamp_seconds %d", at(7).Unix()))
}

// TestTextFormat checks the exposition rules a scraper relies on: one HELP and TYPE per
// family, before its samples, and every line terminated.
func TestTextFormat(t *testing.T) {
	tb := New(time.Hour, 10, BuildInfo{Version: "v", Commit: "c"})
	tb.Finished(lbl("198.51.100.6", 5432), at(1))
	tb.Finished(lbl("2001:db8::6", 53), at(1))
	tb.Refresh(map[flows.Labels]int{lbl("198.51.100.9", 22): 1}, flows.Health{}, true, at(2))
	body := text(t, tb)
	if !strings.HasSuffix(body, "\n") {
		t.Fatal("no trailing newline")
	}
	typed := map[string]bool{}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(body, "\n"), "\n") {
		f := strings.Fields(line)
		switch {
		case strings.HasPrefix(line, "# TYPE "):
			if typed[f[2]] {
				t.Fatalf("second TYPE for %s", f[2])
			}
			typed[f[2]] = true
		case strings.HasPrefix(line, "# HELP "):
		default:
			name := line[:strings.IndexAny(line, "{ ")]
			if !typed[name] {
				t.Fatalf("sample before TYPE: %s", line)
			}
			series := line[:strings.LastIndexByte(line, ' ')]
			if seen[series] {
				t.Fatalf("duplicate series %s", series)
			}
			seen[series] = true
		}
	}
	mustContain(t, body, `ipcx_connections_finished_total{role="known",direction="outbound",proto="tcp",src_ip="192.0.2.10",dst_ip="2001:db8::6",dst_port="53"} 1`)
}

func TestHandler(t *testing.T) {
	tb := New(time.Hour, 10, BuildInfo{})
	tb.Finished(lbl("198.51.100.6", 5432), at(1))
	srv := httptest.NewServer(tb.Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/plain; version=0.0.4; charset=utf-8" {
		t.Fatalf("%d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	mustContain(t, string(b), "ipcx_connections_finished_total{"+pg+"} 1")
}

func TestConcurrentScrapesAndUpdates(t *testing.T) {
	tb := New(time.Hour, 1000, BuildInfo{})
	h := tb.Handler()
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
				if rec.Code != 200 && rec.Code != http.StatusServiceUnavailable {
					t.Errorf("code %d", rec.Code)
				}
			}
		}()
		_ = i
	}
	for i := range 500 {
		tb.Finished(lbl(fmt.Sprintf("198.51.100.%d", i%200), 80), at(i))
		if i%50 == 0 {
			tb.Refresh(map[flows.Labels]int{lbl("198.51.100.1", 80): i}, flows.Health{}, true, at(i))
		}
	}
	wg.Wait()
}
