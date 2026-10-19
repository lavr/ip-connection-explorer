package model

import (
	"fmt"
	"net/netip"
	"time"
)

type Endpoint struct {
	Addr netip.Addr `json:"addr"`
	Port uint16     `json:"port"`
}

func (e Endpoint) String() string {
	if e.Addr.Is6() {
		return fmt.Sprintf("[%s]:%d", e.Addr, e.Port)
	}
	return fmt.Sprintf("%s:%d", e.Addr, e.Port)
}

type Tuple struct {
	Src      Endpoint `json:"src"`
	Dst      Endpoint `json:"dst"`
	Proto    Proto    `json:"proto"`
	ICMPType uint8    `json:"icmp_type,omitempty"`
	ICMPCode uint8    `json:"icmp_code,omitempty"`
	Zone     uint16   `json:"zone,omitempty"`
}

type DepKey struct {
	Scope       string     `json:"scope"`
	Family      uint8      `json:"family"`
	Proto       Proto      `json:"proto"`
	Status      RoleStatus `json:"role_status"`
	Initiator   netip.Addr `json:"initiator,omitzero"`
	Service     netip.Addr `json:"service,omitzero"`
	ServicePort uint16     `json:"service_port,omitempty"`
	ICMPType    uint8      `json:"icmp_type,omitempty"`
	ICMPCode    uint8      `json:"icmp_code,omitempty"`
	A           Endpoint   `json:"endpoint_a,omitzero"`
	B           Endpoint   `json:"endpoint_b,omitzero"`
}

func (k DepKey) String() string {
	return fmt.Sprintf("%s|%d|%d|%s|%s|%s|%d|%d/%d|%s|%s",
		k.Scope, k.Family, k.Proto, k.Status, k.Initiator, k.Service, k.ServicePort,
		k.ICMPType, k.ICMPCode, k.A, k.B)
}

type ObserverRef struct {
	Hostname  string `json:"hostname"`
	MachineID string `json:"machine_id"`
	RunID     string `json:"run_id"`
}

type ProcessRef struct {
	Comm     string   `json:"comm"`
	Endpoint Endpoint `json:"endpoint"`
	Count    uint64   `json:"count"`
}

type Example struct {
	At    time.Time `json:"at"`
	Orig  Tuple     `json:"orig"`
	Reply Tuple     `json:"reply"`
}

type Dependency struct {
	Key                DepKey       `json:"key"`
	Orientation        *Tuple       `json:"orientation,omitempty"`
	Observer           ObserverRef  `json:"observer"`
	Direction          Direction    `json:"direction"`
	FirstSeen          time.Time    `json:"first_seen"`
	LastSeen           time.Time    `json:"last_seen"`
	Sources            []Source     `json:"sources"`
	NewEvents          uint64       `json:"new_events"`
	DestroyEvents      uint64       `json:"destroy_events"`
	FlowsObserved      uint64       `json:"flows_observed"`
	FlowsEstimated     bool         `json:"flows_estimated"`
	EverReplySeen      bool         `json:"ever_reply_seen"`
	EverAssured        bool         `json:"ever_assured"`
	TCPStates          []CTState    `json:"tcp_states,omitempty"`
	Processes          []ProcessRef `json:"processes,omitempty"`
	ProcessesTruncated bool         `json:"processes_truncated,omitempty"`
	Examples           []Example    `json:"examples,omitempty"`
	Evidence           []Evidence   `json:"evidence"`
	Confidence         Confidence   `json:"confidence"`
}

type Gap struct {
	Kind   GapKind   `json:"kind"`
	From   time.Time `json:"from"`
	To     time.Time `json:"to,omitzero"`
	Reason string    `json:"reason"`
}

type Interval struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to,omitzero"`
}

type Coverage struct {
	NetNS             string            `json:"netns"`
	EventsSysctl      int               `json:"events_sysctl"`
	Intervals         []Interval        `json:"intervals"`
	Gaps              []Gap             `json:"gaps"`
	HistoryIncomplete bool              `json:"history_incomplete"`
	Counters          map[string]uint64 `json:"counters"`
}

type LimitsState struct {
	MaxActive             int        `json:"max_active"`
	MaxKnown              int        `json:"max_known"`
	MaxUnknown            int        `json:"max_unknown"`
	Truncated             bool       `json:"truncated"`
	UnknownTruncated      bool       `json:"unknown_truncated"`
	TruncatedSince        *time.Time `json:"truncated_since,omitempty"`
	UnknownTruncatedSince *time.Time `json:"unknown_truncated_since,omitempty"`
	DroppedObservations   uint64     `json:"dropped_observations"`
}
