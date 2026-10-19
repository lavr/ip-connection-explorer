package merge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"

	"github.com/lavr/ip-connection-explorer/internal/checkpoint"
	"github.com/lavr/ip-connection-explorer/internal/model"
)

const Kind = "merged"

type Merged struct {
	SchemaVersion int                `json:"schema_version"`
	Kind          string             `json:"kind"`
	Runs          []checkpoint.File  `json:"runs"`
	Dependencies  []model.Dependency `json:"dependencies"`
	Conflicts     []Conflict         `json:"conflicts,omitempty"`
}

type Conflict struct {
	Transport model.Tuple         `json:"transport"`
	Observers []model.ObserverRef `json:"observers"`
	Keys      []model.DepKey      `json:"keys"`
}

// Merge keeps the latest generation of every run and lists dependencies per observer run.
// Counters are never summed: both ends of one connection report it.
func Merge(files []*checkpoint.File) (*Merged, error) {
	latest := map[string]*checkpoint.File{}
	for _, f := range files {
		cur, ok := latest[f.Run.RunID]
		if !ok {
			latest[f.Run.RunID] = f
			continue
		}
		if cur.Host.MachineID != f.Host.MachineID || cur.Host.BootID != f.Host.BootID || cur.SchemaVersion != f.SchemaVersion {
			return nil, fmt.Errorf("run %s: inputs disagree on machine, boot or schema", f.Run.RunID)
		}
		switch {
		case f.Run.Generation > cur.Run.Generation:
			latest[f.Run.RunID] = f
		case f.Run.Generation == cur.Run.Generation:
			same, err := equalJSON(cur, f)
			if err != nil {
				return nil, err
			}
			if !same {
				return nil, fmt.Errorf("run %s generation %d: two inputs with different content", f.Run.RunID, f.Run.Generation)
			}
		}
	}
	ids := make([]string, 0, len(latest))
	for id := range latest {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	m := &Merged{SchemaVersion: checkpoint.SchemaVersion, Kind: Kind}
	for _, id := range ids {
		f := latest[id]
		hdr := *f
		hdr.Dependencies = nil
		m.Runs = append(m.Runs, hdr)
		m.Dependencies = append(m.Dependencies, f.Dependencies...)
	}
	sort.SliceStable(m.Dependencies, func(i, j int) bool {
		a, b := m.Dependencies[i], m.Dependencies[j]
		if ka, kb := a.Key.String(), b.Key.String(); ka != kb {
			return ka < kb
		}
		return a.Observer.MachineID+a.Observer.RunID < b.Observer.MachineID+b.Observer.RunID
	})
	m.Conflicts = conflicts(m.Dependencies)
	return m, nil
}

func equalJSON(a, b *checkpoint.File) (bool, error) {
	ja, err := json.Marshal(a)
	if err != nil {
		return false, err
	}
	jb, err := json.Marshal(b)
	if err != nil {
		return false, err
	}
	return bytes.Equal(ja, jb), nil
}

type transportKey struct {
	src, dst model.Endpoint
	proto    model.Proto
}

type roleView struct {
	status    model.RoleStatus
	initiator netip.Addr
	service   netip.Addr
	port      uint16
}

// conflicts reports observers that saw the same original tuple but inferred different roles.
func conflicts(deps []model.Dependency) []Conflict {
	type entry struct {
		obs model.ObserverRef
		key model.DepKey
	}
	by := map[transportKey][]entry{}
	var order []transportKey
	for _, d := range deps {
		if d.Key.Scope != "global" {
			continue
		}
		for _, ex := range d.Examples {
			k := transportKey{ex.Orig.Src, ex.Orig.Dst, ex.Orig.Proto}
			if _, ok := by[k]; !ok {
				order = append(order, k)
			}
			by[k] = append(by[k], entry{d.Observer, d.Key})
		}
	}
	var out []Conflict
	for _, k := range order {
		es := by[k]
		views := map[roleView]bool{}
		observers := map[string]bool{}
		for _, e := range es {
			if e.key.Status == model.RoleUnknown {
				continue
			}
			views[roleView{e.key.Status, e.key.Initiator, e.key.Service, e.key.ServicePort}] = true
			observers[e.obs.MachineID+"/"+e.obs.RunID] = true
		}
		if len(views) < 2 || len(observers) < 2 {
			continue
		}
		c := Conflict{Transport: model.Tuple{Src: k.src, Dst: k.dst, Proto: k.proto}}
		for _, e := range es {
			c.Observers = append(c.Observers, e.obs)
			c.Keys = append(c.Keys, e.key)
		}
		out = append(out, c)
	}
	return out
}
