package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/lavr/ip-connection-explorer/internal/checkpoint"
	"github.com/lavr/ip-connection-explorer/internal/merge"
	"github.com/lavr/ip-connection-explorer/internal/model"
)

type Input struct {
	Runs         []checkpoint.File  `json:"runs"`
	Dependencies []model.Dependency `json:"dependencies"`
	Conflicts    []merge.Conflict   `json:"conflicts,omitempty"`
}

type Options struct {
	Format        string
	Role          string
	MinConfidence model.Confidence
	IncludeHidden bool
}

// Load reads a single checkpoint or a merged file.
func Load(path string) (*Input, error) {
	var probe struct {
		Kind string `json:"kind"`
	}
	if err := checkpoint.ReadJSON(path, &probe); err != nil {
		return nil, err
	}
	if probe.Kind == merge.Kind {
		var m merge.Merged
		if err := checkpoint.ReadJSON(path, &m); err != nil {
			return nil, err
		}
		return &Input{Runs: m.Runs, Dependencies: m.Dependencies, Conflicts: m.Conflicts}, nil
	}
	f, err := checkpoint.Read(path)
	if err != nil {
		return nil, err
	}
	hdr := *f
	hdr.Dependencies = nil
	return &Input{Runs: []checkpoint.File{hdr}, Dependencies: f.Dependencies}, nil
}

type hiddenCounts struct{ loopback, forwarded, unresolved int }

func Write(w io.Writer, summary io.Writer, in *Input, opt Options) error {
	var keep []model.Dependency
	var hidden hiddenCounts
	for _, d := range in.Dependencies {
		if !roleMatches(d.Key.Status, opt.Role) || d.Confidence < opt.MinConfidence {
			continue
		}
		if !opt.IncludeHidden {
			switch {
			case strings.HasPrefix(d.Key.Scope, "observer:"):
				hidden.loopback++
				continue
			case d.Direction == model.DirForwarded:
				hidden.forwarded++
				continue
			case d.Direction == model.DirUnresolved:
				hidden.unresolved++
				continue
			}
		}
		keep = append(keep, d)
	}
	status := coverageByRun(in.Runs)
	var err error
	switch opt.Format {
	case "", "csv":
		err = writeCSV(w, keep, status)
	case "json":
		out := *in
		out.Dependencies = keep
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		err = enc.Encode(out)
	default:
		return fmt.Errorf("unknown format %q", opt.Format)
	}
	if err != nil {
		return err
	}
	incomplete, truncated := 0, 0
	for _, s := range status {
		if strings.Contains(s, "incomplete") {
			incomplete++
		}
		if strings.Contains(s, "truncated") {
			truncated++
		}
	}
	fmt.Fprintf(summary, "rows: %d; hidden: %d (loopback %d, forwarded %d, unresolved %d); incomplete runs: %d; truncated runs: %d; conflicts: %d\n",
		len(keep), hidden.loopback+hidden.forwarded+hidden.unresolved, hidden.loopback, hidden.forwarded, hidden.unresolved,
		incomplete, truncated, len(in.Conflicts))
	return nil
}

func roleMatches(s model.RoleStatus, role string) bool {
	switch role {
	case "known":
		return s == model.RoleKnown
	case "unknown":
		return s != model.RoleKnown
	}
	return true
}

func coverageByRun(runs []checkpoint.File) map[string]string {
	out := map[string]string{}
	for _, r := range runs {
		c := r.Coverage
		incomplete := c.HistoryIncomplete || (c.EventsSysctl != 1 && c.EventsSysctl != 2)
		for _, g := range c.Gaps {
			if g.Kind == model.GapMap && g.To.IsZero() {
				incomplete = true
			}
		}
		if n := len(c.Intervals); n == 0 || c.Intervals[n-1].To.IsZero() {
			incomplete = true
		}
		truncated := r.Limits.Truncated || r.Limits.UnknownTruncated
		switch {
		case incomplete && truncated:
			out[r.Run.RunID] = "incomplete+truncated"
		case truncated:
			out[r.Run.RunID] = "truncated"
		case incomplete:
			out[r.Run.RunID] = "incomplete"
		default:
			out[r.Run.RunID] = "complete"
		}
	}
	return out
}
