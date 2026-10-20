// Package exporter keeps a bounded table of connection series and serves it in the
// Prometheus text format.
package exporter

import (
	"bufio"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lavr/ip-connection-explorer/internal/flows"
	"github.com/lavr/ip-connection-explorer/internal/model"
)

const contentType = "text/plain; version=0.0.4; charset=utf-8"

// maxScrapes bounds concurrent scrapes: each holds its own copy of the table.
const maxScrapes = 2

type BuildInfo struct {
	Version, Commit string
}

type series struct {
	finished uint64
	active   int
	lastSeen time.Time
}

type Table struct {
	ttl  time.Duration
	max  int
	info BuildInfo
	sem  chan struct{}

	mu         sync.Mutex
	series     map[flows.Labels]*series
	rejected   uint64
	lastSweep  time.Time
	health     flows.Health
	ready      bool
	snapshotAt time.Time
	checkpoint time.Time
}

func New(ttl time.Duration, maxSeries int, info BuildInfo) *Table {
	return &Table{ttl: ttl, max: maxSeries, info: info, sem: make(chan struct{}, maxScrapes),
		series: map[flows.Labels]*series{}}
}

// Finished counts one ended connection. A new label set on a full table first reclaims
// expired series, at most once a second, and is rejected if there is still no room.
func (t *Table) Finished(l flows.Labels, at time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.series[l]
	if s == nil {
		if len(t.series) >= t.max && at.Sub(t.lastSweep) >= time.Second {
			t.expire(at)
			t.lastSweep = at
		}
		if len(t.series) >= t.max {
			t.rejected++
			return
		}
		s = &series{}
		t.series[l] = s
	}
	s.finished++
	if at.After(s.lastSeen) {
		s.lastSeen = at
	}
}

// Refresh replaces the active counts with a new sample in one step, expires idle series and
// then admits new active label sets in a fixed order, so a full table keeps the same ones.
func (t *Table) Refresh(active map[flows.Labels]int, h flows.Health, ready bool, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for l, s := range t.series {
		s.active = active[l]
		if s.active > 0 {
			s.lastSeen = now
		}
	}
	t.expire(now)
	t.lastSweep = now
	// A full table admits nothing, so the candidates are only counted, not sorted.
	var fresh []flows.Labels
	full := len(t.series) >= t.max
	for l, n := range active {
		if n > 0 && t.series[l] == nil {
			if full {
				t.rejected++
				continue
			}
			fresh = append(fresh, l)
		}
	}
	slices.SortFunc(fresh, compareLabels)
	for _, l := range fresh {
		if len(t.series) >= t.max {
			t.rejected++
			continue
		}
		t.series[l] = &series{active: active[l], lastSeen: now}
	}
	t.health = h
	t.health.OpenGaps = slices.Clone(h.OpenGaps)
	t.ready = ready
	t.snapshotAt = now
}

func (t *Table) CheckpointWritten(at time.Time) {
	t.mu.Lock()
	t.checkpoint = at
	t.mu.Unlock()
}

func (t *Table) expire(now time.Time) {
	for l, s := range t.series {
		if s.active == 0 && now.Sub(s.lastSeen) > t.ttl {
			delete(t.series, l)
		}
	}
}

type row struct {
	l flows.Labels
	s series
}

type view struct {
	rows       []row
	rejected   uint64
	health     flows.Health
	ready      bool
	snapshotAt time.Time
	checkpoint time.Time
}

// copyView holds the lock only for the copy; formatting runs outside it.
func (t *Table) copyView() view {
	t.mu.Lock()
	v := view{rows: make([]row, 0, len(t.series)), rejected: t.rejected, health: t.health,
		ready: t.ready, snapshotAt: t.snapshotAt, checkpoint: t.checkpoint}
	for l, s := range t.series {
		v.rows = append(v.rows, row{l, *s})
	}
	t.mu.Unlock()
	slices.SortFunc(v.rows, func(a, b row) int { return compareLabels(a.l, b.l) })
	return v
}

func compareLabels(a, b flows.Labels) int {
	switch {
	case a.Role != b.Role:
		return int(a.Role) - int(b.Role)
	case a.Direction != b.Direction:
		return int(a.Direction) - int(b.Direction)
	case a.Proto != b.Proto:
		return int(a.Proto) - int(b.Proto)
	}
	if c := a.Src.Compare(b.Src); c != 0 {
		return c
	}
	if c := a.Dst.Compare(b.Dst); c != 0 {
		return c
	}
	return int(a.DstPort) - int(b.DstPort)
}

func (t *Table) WriteText(w io.Writer) error {
	v := t.copyView()
	b := bufio.NewWriter(w)
	family := func(name, typ, help string) {
		b.WriteString("# HELP " + name + " " + escapeHelp(help) + "\n# TYPE " + name + " " + typ + "\n")
	}
	sample := func(name, labels string, value string) {
		b.WriteString(name)
		if labels != "" {
			b.WriteString("{" + labels + "}")
		}
		b.WriteString(" " + value + "\n")
	}
	u := func(n uint64) string { return strconv.FormatUint(n, 10) }
	boolean := func(x bool) string {
		if x {
			return "1"
		}
		return "0"
	}

	family("ipcx_connections_finished_total", "counter",
		"Connection lifetimes the collector saw end, by their final role. Counts are kept since the series appeared; a series idle for longer than the TTL is removed and starts again from zero.")
	for _, r := range v.rows {
		sample("ipcx_connections_finished_total", connLabels(r.l), u(r.s.finished))
	}
	family("ipcx_connections_active", "gauge",
		"Connections open at the last active sample (taken every --snapshot-every).")
	for _, r := range v.rows {
		sample("ipcx_connections_active", connLabels(r.l), strconv.Itoa(r.s.active))
	}

	family("ipcx_build_info", "gauge", "ipcx build.")
	sample("ipcx_build_info", `version="`+escapeValue(t.info.Version)+`",commit="`+escapeValue(t.info.Commit)+`"`, "1")
	family("ipcx_exporter_ready", "gauge", "1 once the first conntrack dump was applied; until then the matrix is not complete.")
	sample("ipcx_exporter_ready", "", boolean(v.ready))
	family("ipcx_exporter_series", "gauge", "Label sets in the exporter table; each is one finished and one active series.")
	sample("ipcx_exporter_series", "", strconv.Itoa(len(v.rows)))
	family("ipcx_exporter_series_rejected_total", "counter", "Admissions of a new label set refused because the table was full; not a count of distinct pairs.")
	sample("ipcx_exporter_series_rejected_total", "", u(v.rejected))
	family("ipcx_exporter_active_snapshot_timestamp_seconds", "gauge", "When the active counts were last sampled.")
	if !v.snapshotAt.IsZero() {
		sample("ipcx_exporter_active_snapshot_timestamp_seconds", "", strconv.FormatInt(v.snapshotAt.Unix(), 10))
	}
	family("ipcx_flows_active", "gauge", "Conntrack entries the collector tracks.")
	sample("ipcx_flows_active", "", strconv.Itoa(v.health.ActiveFlows))
	family("ipcx_flows_rejected_total", "counter", "Observations dropped because --max-active was reached; one entry can be dropped many times.")
	sample("ipcx_flows_rejected_total", "", u(v.health.ActiveRejected))
	family("ipcx_gaps_total", "counter", "Gaps opened: periods when connections could be missed.")
	sample("ipcx_gaps_total", "", u(v.health.GapsOpened))
	family("ipcx_gap_open", "gauge", "1 while a gap of this kind is open.")
	for _, k := range []model.GapKind{model.GapMap, model.GapAttribution} {
		sample("ipcx_gap_open", `kind="`+k.String()+`"`, boolean(slices.Contains(v.health.OpenGaps, k)))
	}
	if !v.checkpoint.IsZero() {
		family("ipcx_last_checkpoint_timestamp_seconds", "gauge", "When the last checkpoint was written.")
		sample("ipcx_last_checkpoint_timestamp_seconds", "", strconv.FormatInt(v.checkpoint.Unix(), 10))
	}
	return b.Flush()
}

func connLabels(l flows.Labels) string {
	return `role="` + l.Role.String() + `",direction="` + l.Direction.String() + `",proto="` + l.Proto.String() +
		`",src_ip="` + l.Src.String() + `",dst_ip="` + l.Dst.String() + `",dst_port="` + strconv.Itoa(int(l.DstPort)) + `"`
}

var valueEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
var helpEscaper = strings.NewReplacer(`\`, `\\`, "\n", `\n`)

func escapeValue(s string) string { return valueEscaper.Replace(s) }
func escapeHelp(s string) string  { return helpEscaper.Replace(s) }

// Handler serves the table. Scrapes beyond maxScrapes get 503 instead of queueing.
func (t *Table) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case t.sem <- struct{}{}:
			defer func() { <-t.sem }()
		default:
			http.Error(w, "too many concurrent scrapes", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", contentType)
		_ = t.WriteText(w)
	})
}
