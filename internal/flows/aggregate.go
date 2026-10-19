package flows

import (
	"slices"
	"time"

	"github.com/lavr/ip-connection-explorer/internal/model"
)

type procKey struct {
	comm string
	ep   model.Endpoint
}

// agg accumulates finished lifetimes of one dependency; active lifetimes are merged in at snapshot time.
type agg struct {
	first, last      time.Time
	sources          map[model.Source]bool
	newEv, destroyEv uint64
	flows            uint64
	reply, assured   bool
	tcp              map[model.CTState]bool
	procs            map[procKey]uint64
	procOrder        []procKey
	procsTrunc       bool
	examples         []model.Example
	evidence         map[model.Evidence]bool
	conf             model.Confidence
	dir              model.Direction
	orient           *model.Tuple
}

func newAgg() *agg {
	return &agg{
		sources:  map[model.Source]bool{},
		tcp:      map[model.CTState]bool{},
		procs:    map[procKey]uint64{},
		evidence: map[model.Evidence]bool{},
	}
}

func (a *agg) clone() *agg {
	c := *a
	c.sources = cloneMap(a.sources)
	c.tcp = cloneMap(a.tcp)
	c.procs = cloneMap(a.procs)
	c.evidence = cloneMap(a.evidence)
	c.procOrder = slices.Clone(a.procOrder)
	c.examples = slices.Clone(a.examples)
	if a.orient != nil {
		o := *a.orient
		c.orient = &o
	}
	return &c
}

func cloneMap[K comparable, V any](m map[K]V) map[K]V {
	c := make(map[K]V, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

func (a *agg) mergeFlow(f *activeFlow, lim Limits) {
	if a.flows == 0 {
		a.first, a.last = f.first, f.last
		a.dir = f.dir
		a.conf = f.inf.Confidence
	}
	if f.first.Before(a.first) {
		a.first = f.first
	}
	if f.last.After(a.last) {
		a.last = f.last
	}
	a.flows++
	a.newEv += f.newEv
	a.destroyEv += f.destroyEv
	a.reply = a.reply || f.ct.SeenReply
	a.assured = a.assured || f.ct.Assured
	for s := range f.sources {
		a.sources[s] = true
	}
	for s := range f.tcp {
		a.tcp[s] = true
	}
	for _, e := range f.inf.Evidence {
		a.evidence[e] = true
	}
	if f.inf.Confidence > a.conf {
		a.conf = f.inf.Confidence
	}
	if a.orient == nil && f.inf.Status != model.RoleKnown {
		o := f.ct.Orig
		a.orient = &o
	}
	for _, pk := range f.procOrder {
		if _, ok := a.procs[pk]; ok {
			a.procs[pk]++
			continue
		}
		if !under(len(a.procOrder), lim.MaxProcesses) {
			a.procsTrunc = true
			continue
		}
		a.procs[pk] = 1
		a.procOrder = append(a.procOrder, pk)
	}
	if under(len(a.examples), lim.MaxExamples) {
		ex := model.Example{At: f.first, Orig: f.ct.Orig, Reply: f.ct.Reply}
		if !slices.ContainsFunc(a.examples, func(e model.Example) bool { return e.Orig == ex.Orig && e.Reply == ex.Reply }) {
			a.examples = append(a.examples, ex)
		}
	}
}

func (a *agg) dependency(key model.DepKey, obs model.ObserverRef, estimated bool) model.Dependency {
	d := model.Dependency{
		Key:                key,
		Observer:           obs,
		Direction:          a.dir,
		FirstSeen:          a.first,
		LastSeen:           a.last,
		Sources:            sortedKeys(a.sources),
		NewEvents:          a.newEv,
		DestroyEvents:      a.destroyEv,
		FlowsObserved:      a.flows,
		FlowsEstimated:     estimated,
		EverReplySeen:      a.reply,
		EverAssured:        a.assured,
		TCPStates:          sortedKeys(a.tcp),
		ProcessesTruncated: a.procsTrunc,
		Examples:           slices.Clone(a.examples),
		Evidence:           sortedKeys(a.evidence),
		Confidence:         a.conf,
	}
	for _, pk := range a.procOrder {
		d.Processes = append(d.Processes, model.ProcessRef{Comm: pk.comm, Endpoint: pk.ep, Count: a.procs[pk]})
	}
	if a.orient != nil {
		o := *a.orient
		d.Orientation = &o
	}
	return d
}

func sortedKeys[K ~uint8](m map[K]bool) []K {
	out := make([]K, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
