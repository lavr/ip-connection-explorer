package report

import (
	"testing"
	"time"

	"github.com/lavr/ip-connection-explorer/internal/checkpoint"
	"github.com/lavr/ip-connection-explorer/internal/model"
)

func run(mod func(*checkpoint.File)) checkpoint.File {
	f := checkpoint.File{Run: checkpoint.Run{RunID: "r1"}}
	f.Coverage.EventsSysctl = 1
	f.Coverage.Intervals = []model.Interval{{From: t0, To: t0.Add(time.Hour)}}
	mod(&f)
	return f
}

func TestCoverageStatusRules(t *testing.T) {
	cases := map[string]struct {
		mod  func(*checkpoint.File)
		want string
	}{
		"complete":         {func(*checkpoint.File) {}, "complete"},
		"events disabled":  {func(f *checkpoint.File) { f.Coverage.EventsSysctl = 0 }, "incomplete"},
		"events unknown":   {func(f *checkpoint.File) { f.Coverage.EventsSysctl = -1 }, "incomplete"},
		"still running":    {func(f *checkpoint.File) { f.Coverage.Intervals[0].To = time.Time{} }, "incomplete"},
		"attribution only": {func(f *checkpoint.File) { f.Coverage.Gaps = []model.Gap{{Kind: model.GapAttribution, From: t0}} }, "complete"},
		"open map gap":     {func(f *checkpoint.File) { f.Coverage.Gaps = []model.Gap{{Kind: model.GapMap, From: t0}} }, "incomplete"},
		"truncated":        {func(f *checkpoint.File) { f.Limits.Truncated = true }, "truncated"},
		"both": {func(f *checkpoint.File) {
			f.Limits.UnknownTruncated = true
			f.Coverage.HistoryIncomplete = true
		}, "incomplete+truncated"},
	}
	for name, c := range cases {
		if got := coverageByRun([]checkpoint.File{run(c.mod)})["r1"]; got != c.want {
			t.Errorf("%s: got %s want %s", name, got, c.want)
		}
	}
}
