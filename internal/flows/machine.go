package flows

import (
	"maps"
	"net/netip"
	"slices"
	"sort"
	"time"

	"github.com/lavr/ip-connection-explorer/internal/model"
)

type EventKind uint8

const (
	EventNew EventKind = iota + 1
	EventUpdate
	EventDestroy
)

type CTEvent struct {
	Kind  EventKind
	At    time.Time
	Epoch uint64
	Flow  CTFlow
}

type DumpResult struct {
	Attempt, Epoch    uint64
	Started, Finished time.Time
	Flows             []CTFlow
	Complete          bool
	Baseline          bool
}

type SockSnapshot struct {
	At       time.Time
	Sockets  []Socket
	Complete bool
}

type Proc struct {
	PID       int
	Comm      string
	StartTime uint64
}

type ProcIndex struct {
	At      time.Time
	ByInode map[uint32][]Proc
}

type AddrSeen struct {
	Addr      netip.Addr `json:"addr"`
	FirstSeen time.Time  `json:"first_seen"`
	LastSeen  time.Time  `json:"last_seen"`
}

type State struct {
	Dependencies []model.Dependency
	Coverage     model.Coverage
	Limits       model.LimitsState
	Addresses    []AddrSeen
}

type flowID struct{ orig, reply model.Tuple }

// tomb marks a lifetime that ended, so late events and stale dumps do not recreate it.
type tomb struct {
	at   time.Time
	ctID uint32
	seq  uint64
}

type tombRef struct {
	id  flowID
	at  time.Time
	seq uint64
}

const sweepEvery = 1024

func (m *Machine) addTomb(id flowID, t tomb) {
	m.tombSeq++
	t.seq = m.tombSeq
	m.tombs[id] = t
	m.tombQ = append(m.tombQ, tombRef{id, t.at, t.seq})
	if len(m.tombQ) > 2*len(m.tombs)+sweepEvery {
		m.compactTombs()
	}
	if m.lim.MaxActive > 0 && len(m.tombs) > m.lim.MaxActive {
		m.sweepTombs(t.at)
		for len(m.tombs) > m.lim.MaxActive && len(m.tombQ) > 0 {
			m.popTomb()
			m.Count("tombstones_evicted", 1)
		}
	}
}

// compactTombs drops queue entries whose tombstone was replaced or removed.
func (m *Machine) compactTombs() {
	live := m.tombQ[:0]
	for _, r := range m.tombQ {
		if t, ok := m.tombs[r.id]; ok && t.seq == r.seq {
			live = append(live, r)
		}
	}
	m.tombQ = live
}

func (m *Machine) popTomb() {
	r := m.tombQ[0]
	m.tombQ = m.tombQ[1:]
	if t, ok := m.tombs[r.id]; ok && t.seq == r.seq {
		delete(m.tombs, r.id)
	}
}

// sweepTombs drops tombstones older than the TTL; the queue is in insertion order.
func (m *Machine) sweepTombs(now time.Time) {
	for len(m.tombQ) > 0 && now.Sub(m.tombQ[0].at) > m.tombstoneTTL {
		m.popTomb()
	}
	m.sinceSweep = 0
}

func idOf(f CTFlow) flowID { return flowID{f.Orig, f.Reply} }

type activeFlow struct {
	id         flowID
	ct         CTFlow
	ev         FlowEvidence
	first      time.Time
	last       time.Time
	touched    time.Time
	sources    map[model.Source]bool
	tcp        map[model.CTState]bool
	newEv      uint64
	destroyEv  uint64
	procs      map[procKey]bool
	procOrder  []procKey
	procsTrunc bool
	inf        Inference
	dir        model.Direction
	key        model.DepKey
	attached   bool
	labels     Labels
}

// Machine is the single owner of collection state. It is not safe for concurrent use.
type Machine struct {
	host         HostContext
	observer     model.ObserverRef
	lim          Limits
	sockMaxAge   time.Duration
	tombstoneTTL time.Duration

	addrs       map[netip.Addr]*AddrSeen
	active      map[flowID]*activeFlow
	tombs       map[flowID]tomb
	tombQ       []tombRef
	tombSeq     uint64
	sinceSweep  int
	records     map[model.DepKey]*agg
	refs        map[model.DepKey]int
	knownKeys   int
	unknownKeys int

	epoch       uint64
	lastAttempt uint64

	listen *ListenIndex
	sidx   *socketIndex
	sockAt time.Time
	procs  ProcIndex

	estimated bool
	cov       model.Coverage

	onFinish       func(Labels, time.Time)
	noReport       bool
	gapsOpened     uint64
	activeRejected uint64

	// Work counters for tests and benchmarks.
	attrProbes        int
	reclassifications int
	limits            model.LimitsState
}

func NewMachine(host HostContext, observer model.ObserverRef, lim Limits, sockMaxAge, tombstoneTTL time.Duration) *Machine {
	if host.ListenMaxAge == 0 {
		host.ListenMaxAge = sockMaxAge
	}
	return &Machine{
		host:         host,
		observer:     observer,
		lim:          lim,
		sockMaxAge:   sockMaxAge,
		tombstoneTTL: tombstoneTTL,
		addrs:        map[netip.Addr]*AddrSeen{},
		active:       map[flowID]*activeFlow{},
		tombs:        map[flowID]tomb{},
		records:      map[model.DepKey]*agg{},
		refs:         map[model.DepKey]int{},
		cov:          model.Coverage{NetNS: "current", Counters: map[string]uint64{}},
		limits:       model.LimitsState{MaxActive: lim.MaxActive, MaxKnown: lim.MaxKnown, MaxUnknown: lim.MaxUnknown},
	}
}

func (m *Machine) Has(a netip.Addr) bool {
	_, ok := m.addrs[model.NormalizeAddr(a)]
	return ok
}

func (m *Machine) ActiveCount() int { return len(m.active) }

func (m *Machine) SetEpoch(e uint64) {
	if e > m.epoch {
		m.epoch = e
	}
}

func (m *Machine) SetAddresses(addrs []netip.Addr, at time.Time) {
	added := false
	for _, a := range addrs {
		a = model.NormalizeAddr(a)
		if s, ok := m.addrs[a]; ok {
			s.LastSeen = at
			continue
		}
		m.addrs[a] = &AddrSeen{Addr: a, FirstSeen: at, LastSeen: at}
		added = true
	}
	// Locality only changes when an address appears: addresses are never forgotten.
	if added {
		m.reclassifyAll(at)
	}
}

func (m *Machine) ApplyEvent(ev CTEvent) {
	if ev.Epoch < m.epoch {
		m.Count("stale_events", 1)
		return
	}
	id := idOf(ev.Flow)
	f := m.active[id]
	if ev.Kind == EventNew {
		if f != nil && !sameLifetime(f.ct.ID, ev.Flow.ID) {
			m.finish(f, ev.At)
			f = nil
		}
		if f == nil {
			delete(m.tombs, id)
			if f = m.create(ev.Flow, ev.At); f == nil {
				return
			}
		}
		if !f.ev.SawNew {
			f.ev.SawNew = true
			if ev.Flow.HasTCPState {
				f.ev.NewState = ev.Flow.TCPState
			}
			f.newEv++
		}
	} else if f == nil {
		if tb, ok := m.tombs[id]; ok && (tb.ctID == 0 || ev.Flow.ID == 0 || tb.ctID == ev.Flow.ID) {
			m.Count("late_events", 1)
			return
		}
		if f = m.create(ev.Flow, ev.At); f == nil {
			return
		}
	}
	m.observe(f, ev.Flow, model.SourceEvent, ev.At)
	if ev.At.After(f.touched) {
		f.touched = ev.At
	}
	m.reclassify(f, ev.At)
	m.attribute(f)
	if ev.Kind == EventDestroy {
		f.destroyEv++
		m.finish(f, ev.At)
		m.addTomb(id, tomb{at: ev.At, ctID: ev.Flow.ID})
	}
	if m.sinceSweep++; m.sinceSweep >= sweepEvery {
		m.sweepTombs(ev.At)
	}
}

// sameLifetime treats a NEW for a flow already seen (in a dump or an earlier NEW) as the same
// kernel entry when the conntrack IDs match. A zero ID carries no information.
func sameLifetime(a, b uint32) bool { return a != 0 && a == b }

func (m *Machine) ApplyDump(res DumpResult) {
	if res.Epoch < m.epoch || (res.Attempt != 0 && res.Attempt <= m.lastAttempt) {
		m.Count("stale_dumps", 1)
		return
	}
	if res.Attempt != 0 {
		m.lastAttempt = res.Attempt
	}
	src := model.SourceDump
	if res.Baseline {
		src = model.SourceBaseline
	}
	seen := make(map[flowID]bool, len(res.Flows))
	for _, c := range res.Flows {
		id := idOf(c)
		seen[id] = true
		if tb, ok := m.tombs[id]; ok && !tb.at.Before(res.Started) {
			continue
		}
		f := m.active[id]
		if f == nil {
			delete(m.tombs, id)
			if f = m.create(c, res.Finished); f == nil {
				continue
			}
		}
		m.observe(f, c, src, res.Finished)
		if res.Started.After(f.touched) {
			f.touched = res.Started
		}
		m.reclassify(f, res.Finished)
		m.attribute(f)
	}
	if res.Complete {
		for id, f := range m.active {
			if !seen[id] && f.touched.Before(res.Started) {
				m.finish(f, res.Finished)
				m.addTomb(id, tomb{at: res.Started, ctID: f.ct.ID})
			}
		}
	}
	m.sweepTombs(res.Finished)
}

func (m *Machine) ApplySockets(s SockSnapshot) {
	m.sidx = newSocketIndex(s.Sockets)
	m.sockAt = s.At
	m.listen = NewListenIndex(s.Sockets, s.At)
	m.reclassifyAll(s.At)
}

func (m *Machine) ApplyProcIndex(p ProcIndex) {
	m.procs = p
	for _, f := range m.active {
		m.attribute(f)
	}
}

func (m *Machine) OpenGap(kind model.GapKind, reason string, at time.Time) {
	m.gapsOpened++
	m.cov.Gaps = append(m.cov.Gaps, model.Gap{Kind: kind, From: at, Reason: reason})
	if kind == model.GapMap {
		m.cov.HistoryIncomplete = true
		m.estimated = true
	}
}

func (m *Machine) CloseGap(kind model.GapKind, at time.Time) {
	for i := len(m.cov.Gaps) - 1; i >= 0; i-- {
		g := &m.cov.Gaps[i]
		if g.Kind == kind && g.To.IsZero() {
			g.To = at
			if m.noReport {
				m.cov.Gaps = slices.Delete(m.cov.Gaps, i, i+1)
			}
			return
		}
	}
}

func (m *Machine) HasOpenGap(kind model.GapKind) bool {
	for _, g := range m.cov.Gaps {
		if g.Kind == kind && g.To.IsZero() {
			return true
		}
	}
	return false
}

func (m *Machine) MarkRestartEstimate()        { m.estimated = true }
func (m *Machine) Count(name string, n uint64) { m.cov.Counters[name] += n }
func (m *Machine) SetEventsSysctl(v int)       { m.cov.EventsSysctl = v }
func (m *Machine) StartInterval(at time.Time) {
	m.cov.Intervals = append(m.cov.Intervals, model.Interval{From: at})
}

func (m *Machine) EndInterval(at time.Time) {
	if n := len(m.cov.Intervals); n > 0 && m.cov.Intervals[n-1].To.IsZero() {
		m.cov.Intervals[n-1].To = at
	}
}

func (m *Machine) create(c CTFlow, at time.Time) *activeFlow {
	if !under(len(m.active), m.lim.MaxActive) {
		m.activeRejected++
		m.markTruncated(false, at)
		return nil
	}
	f := &activeFlow{
		id: idOf(c), ct: c, first: at, last: at,
		sources: map[model.Source]bool{},
		tcp:     map[model.CTState]bool{},
		procs:   map[procKey]bool{},
	}
	m.active[f.id] = f
	return f
}

func (m *Machine) observe(f *activeFlow, c CTFlow, src model.Source, at time.Time) {
	f.sources[src] = true
	if at.After(f.last) {
		f.last = at
	}
	f.ct.ID = c.ID
	f.ct.SeenReply = f.ct.SeenReply || c.SeenReply
	f.ct.Assured = f.ct.Assured || c.Assured
	if c.HasTCPState {
		f.ct.TCPState, f.ct.HasTCPState = c.TCPState, true
		f.tcp[c.TCPState] = true
		if c.TCPState == model.CTSynSent2 {
			f.ev.SawSimultaneousOpen = true
		}
	}
}

func (m *Machine) finish(f *activeFlow, at time.Time) {
	delete(m.active, f.id)
	if m.onFinish != nil {
		m.onFinish(f.labels, at)
	}
	if !f.attached {
		return
	}
	rec := m.records[f.key]
	if rec == nil {
		rec = newAgg()
		m.records[f.key] = rec
	} else {
		m.release(f.key)
	}
	rec.mergeFlow(f, m.lim)
	f.attached = false
}

func (m *Machine) reclassifyAll(at time.Time) {
	for _, f := range m.active {
		m.reclassify(f, at)
		m.attribute(f)
	}
}

func (m *Machine) reclassify(f *activeFlow, now time.Time) {
	m.reclassifications++
	prevInf, prevDir := f.inf, f.dir
	f.inf = Classify(f.ct, f.ev, m.listen, m, m.host, now)
	f.dir = m.direction(f)
	f.labels = m.labelsFor(f)
	if m.noReport {
		return
	}
	key := m.keyFor(f)
	if f.attached && f.key == key {
		return
	}
	if !m.acquire(key, now) {
		// Keep the flow on its previous record, with the inference that record was built
		// from, rather than dropping what was already observed.
		if f.attached {
			f.inf, f.dir = prevInf, prevDir
		}
		return
	}
	if f.attached {
		m.release(f.key)
	}
	f.key, f.attached = key, true
}

func (m *Machine) acquire(key model.DepKey, at time.Time) bool {
	if m.refs[key] > 0 {
		m.refs[key]++
		return true
	}
	known := !unknownBudget(key)
	if known && !under(m.knownKeys, m.lim.MaxKnown) || !known && !under(m.unknownKeys, m.lim.MaxUnknown) {
		m.markTruncated(!known, at)
		return false
	}
	m.refs[key] = 1
	if known {
		m.knownKeys++
	} else {
		m.unknownKeys++
	}
	return true
}

func (m *Machine) release(key model.DepKey) {
	m.refs[key]--
	if m.refs[key] > 0 {
		return
	}
	delete(m.refs, key)
	if !unknownBudget(key) {
		m.knownKeys--
	} else {
		m.unknownKeys--
	}
}

// unknownBudget: unknown and conflict records keep both ports and use their own budget, so they
// cannot exhaust the space for dependencies with a known role.
func unknownBudget(k model.DepKey) bool { return k.Status != model.RoleKnown }

func (m *Machine) direction(f *activeFlow) model.Direction {
	o, r := f.ct.Orig, f.ct.Reply
	if !m.Has(o.Src.Addr) && !m.Has(o.Dst.Addr) {
		if m.Has(r.Src.Addr) || m.Has(r.Dst.Addr) {
			return model.DirUnresolved
		}
		return model.DirForwarded
	}
	init, svc := o.Src.Addr, o.Dst.Addr
	if f.inf.Status == model.RoleKnown {
		init, svc = f.inf.Initiator.Addr, f.inf.Service.Addr
	}
	switch il, sl := m.Has(init), m.Has(svc); {
	case il && sl:
		return model.DirLocal
	case il:
		return model.DirOutbound
	default:
		return model.DirInbound
	}
}

func (m *Machine) keyFor(f *activeFlow) model.DepKey {
	o := f.ct.Orig
	scope := "global"
	for _, a := range []netip.Addr{o.Src.Addr, o.Dst.Addr} {
		if s := model.ScopeFor(a, m.host.MachineID); s != "global" {
			scope = s
		}
	}
	k := model.DepKey{Scope: scope, Family: model.Family(o.Dst.Addr), Proto: o.Proto, Status: f.inf.Status}
	if f.inf.Status == model.RoleKnown {
		k.Initiator = model.NormalizeAddr(f.inf.Initiator.Addr)
		k.Service = model.NormalizeAddr(f.inf.Service.Addr)
		if o.Proto.IsICMP() {
			k.ICMPType, k.ICMPCode = o.ICMPType, o.ICMPCode
		} else {
			k.ServicePort = f.inf.Service.Port
		}
		return k
	}
	// Endpoints keep the original orientation, so opposite first packets stay separate records.
	// A local ephemeral port is recorded as 0, or every client query would be its own record.
	k.A, k.B = m.collapse(o.Proto, normEP(o.Src)), m.collapse(o.Proto, normEP(o.Dst))
	return k
}

// collapse omits a local port that falls in the ephemeral range, unless something on the host
// listens on or is bound to it.
func (m *Machine) collapse(proto model.Proto, e model.Endpoint) model.Endpoint {
	if !m.Has(e.Addr) || !m.host.ephemeral(e.Port) {
		return e
	}
	if proto == model.ProtoTCP && m.listen.Match(proto, e, time.Time{}, 0) != MatchNone {
		return e
	}
	if proto == model.ProtoUDP && m.listen.UDPBound(e, time.Time{}, 0) {
		return e
	}
	e.Port = 0
	return e
}

func normEP(e model.Endpoint) model.Endpoint {
	return model.Endpoint{Addr: model.NormalizeAddr(e.Addr), Port: e.Port}
}

// attribute links local endpoints of a flow to processes via the latest socket snapshot and process index.
func (m *Machine) attribute(f *activeFlow) {
	if m.sidx == nil || len(m.procs.ByInode) == 0 || f.ct.Orig.Proto.IsICMP() {
		return
	}
	if m.sockMaxAge > 0 && (f.last.Sub(m.sockAt) > m.sockMaxAge || f.last.Sub(m.procs.At) > m.sockMaxAge) {
		return
	}
	o := f.ct.Orig
	for _, side := range [2][2]model.Endpoint{{o.Src, o.Dst}, {o.Dst, o.Src}} {
		local, remote := normEP(side[0]), normEP(side[1])
		if !m.Has(local.Addr) {
			continue
		}
		m.attrProbes += m.sidx.each(o.Proto, local, remote, func(s Socket) {
			for _, p := range m.procs.ByInode[s.Inode] {
				pk := procKey{comm: p.Comm, ep: local}
				if f.procs[pk] {
					continue
				}
				if !under(len(f.procOrder), m.lim.MaxProcesses) {
					f.procsTrunc = true
					continue
				}
				f.procs[pk] = true
				f.procOrder = append(f.procOrder, pk)
			}
		})
	}
}

func socketMatches(s Socket, local, remote model.Endpoint) bool {
	sl := normEP(s.Local)
	if sl.Port != local.Port || (sl.Addr != local.Addr && !sl.Addr.IsUnspecified()) {
		return false
	}
	if s.Proto == model.ProtoTCP {
		return s.State != model.SockListen && normEP(s.Remote) == remote
	}
	if r := normEP(s.Remote); r.Addr.IsValid() && !r.Addr.IsUnspecified() {
		return r == remote
	}
	return true
}

func (m *Machine) Snapshot() State {
	aggs := make(map[model.DepKey]*agg, len(m.records))
	for k, a := range m.records {
		aggs[k] = a.clone()
	}
	for _, f := range m.active {
		if !f.attached {
			continue
		}
		a := aggs[f.key]
		if a == nil {
			a = newAgg()
			aggs[f.key] = a
		}
		a.mergeFlow(f, m.lim)
	}
	st := State{Limits: m.limits, Coverage: m.cov}
	for k, a := range aggs {
		st.Dependencies = append(st.Dependencies, a.dependency(k, m.observer, m.estimated))
	}
	sort.Slice(st.Dependencies, func(i, j int) bool {
		return st.Dependencies[i].Key.String() < st.Dependencies[j].Key.String()
	})
	st.Coverage.Intervals = slices.Clone(m.cov.Intervals)
	st.Coverage.Gaps = slices.Clone(m.cov.Gaps)
	st.Coverage.Counters = maps.Clone(m.cov.Counters)
	if m.limits.TruncatedSince != nil {
		t := *m.limits.TruncatedSince
		st.Limits.TruncatedSince = &t
	}
	if m.limits.UnknownTruncatedSince != nil {
		t := *m.limits.UnknownTruncatedSince
		st.Limits.UnknownTruncatedSince = &t
	}
	for _, a := range m.addrs {
		st.Addresses = append(st.Addresses, *a)
	}
	sort.Slice(st.Addresses, func(i, j int) bool {
		ai, aj := st.Addresses[i], st.Addresses[j]
		if !ai.FirstSeen.Equal(aj.FirstSeen) {
			return ai.FirstSeen.Before(aj.FirstSeen)
		}
		return ai.Addr.Less(aj.Addr)
	})
	return st
}
