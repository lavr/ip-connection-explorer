package model

import (
	"fmt"
	"strconv"
)

type Proto uint8

const (
	ProtoICMP   Proto = 1
	ProtoTCP    Proto = 6
	ProtoUDP    Proto = 17
	ProtoICMPv6 Proto = 58
)

func (p Proto) String() string {
	switch p {
	case ProtoICMP:
		return "icmp"
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoICMPv6:
		return "icmpv6"
	}
	return strconv.Itoa(int(p))
}

func (p Proto) IsICMP() bool { return p == ProtoICMP || p == ProtoICMPv6 }

// CTState is the conntrack TCP state (enum tcp_conntrack). It is not the socket TCP state.
type CTState uint8

const (
	CTNone CTState = iota
	CTSynSent
	CTSynRecv
	CTEstablished
	CTFinWait
	CTCloseWait
	CTLastAck
	CTTimeWait
	CTClose
	CTSynSent2
)

// SockState is the socket TCP state (include/net/tcp_states.h). It is not the conntrack state.
type SockState uint8

const (
	SockEstablished SockState = iota + 1
	SockSynSent
	SockSynRecv
	SockFinWait1
	SockFinWait2
	SockTimeWait
	SockClose
	SockCloseWait
	SockLastAck
	SockListen
	SockClosing
)

type textEnum[T ~uint8] struct{ names []string }

func (e textEnum[T]) marshal(v T) ([]byte, error) {
	if int(v) >= len(e.names) {
		return nil, fmt.Errorf("invalid value %d", v)
	}
	return []byte(e.names[v]), nil
}

func (e textEnum[T]) unmarshal(b []byte, v *T) error {
	for i, n := range e.names {
		if n == string(b) {
			*v = T(i)
			return nil
		}
	}
	return fmt.Errorf("invalid value %q", b)
}

func (e textEnum[T]) str(v T) string {
	if int(v) >= len(e.names) {
		return strconv.Itoa(int(v))
	}
	return e.names[v]
}

type RoleStatus uint8

const (
	RoleKnown RoleStatus = iota
	RoleUnknown
	RoleConflict
)

var roleNames = textEnum[RoleStatus]{[]string{"known", "unknown", "conflict"}}

func (v RoleStatus) String() string                { return roleNames.str(v) }
func (v RoleStatus) MarshalText() ([]byte, error)  { return roleNames.marshal(v) }
func (v *RoleStatus) UnmarshalText(b []byte) error { return roleNames.unmarshal(b, v) }

type Confidence uint8

const (
	ConfidenceLow Confidence = iota
	ConfidenceMedium
	ConfidenceHigh
)

var confidenceNames = textEnum[Confidence]{[]string{"low", "medium", "high"}}

func (v Confidence) String() string                { return confidenceNames.str(v) }
func (v Confidence) MarshalText() ([]byte, error)  { return confidenceNames.marshal(v) }
func (v *Confidence) UnmarshalText(b []byte) error { return confidenceNames.unmarshal(b, v) }

type Evidence uint8

const (
	EvidenceNone Evidence = iota
	EvidenceConntrackNew
	EvidenceConntrackOriginal
	EvidenceListen
	EvidenceListenContradicts
	EvidencePortRange
	EvidenceUDPBound
	EvidenceSNAT
)

var evidenceNames = textEnum[Evidence]{[]string{"none", "conntrack_new", "conntrack_original", "listen", "listen_contradicts", "port_range", "udp_bound", "conntrack_snat"}}

func (v Evidence) String() string                { return evidenceNames.str(v) }
func (v Evidence) MarshalText() ([]byte, error)  { return evidenceNames.marshal(v) }
func (v *Evidence) UnmarshalText(b []byte) error { return evidenceNames.unmarshal(b, v) }

type Direction uint8

const (
	DirUnresolved Direction = iota
	DirInbound
	DirOutbound
	DirLocal
	DirForwarded
)

var directionNames = textEnum[Direction]{[]string{"unresolved", "inbound", "outbound", "local", "forwarded"}}

func (v Direction) String() string                { return directionNames.str(v) }
func (v Direction) MarshalText() ([]byte, error)  { return directionNames.marshal(v) }
func (v *Direction) UnmarshalText(b []byte) error { return directionNames.unmarshal(b, v) }

type Source uint8

const (
	SourceBaseline Source = iota
	SourceEvent
	SourceDump
	SourceSockdiag
)

var sourceNames = textEnum[Source]{[]string{"baseline", "event", "dump", "sockdiag"}}

func (v Source) String() string                { return sourceNames.str(v) }
func (v Source) MarshalText() ([]byte, error)  { return sourceNames.marshal(v) }
func (v *Source) UnmarshalText(b []byte) error { return sourceNames.unmarshal(b, v) }

type GapKind uint8

const (
	GapMap GapKind = iota
	GapAttribution
)

var gapNames = textEnum[GapKind]{[]string{"map", "attribution"}}

func (v GapKind) String() string                { return gapNames.str(v) }
func (v GapKind) MarshalText() ([]byte, error)  { return gapNames.marshal(v) }
func (v *GapKind) UnmarshalText(b []byte) error { return gapNames.unmarshal(b, v) }
