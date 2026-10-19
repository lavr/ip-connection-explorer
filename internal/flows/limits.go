package flows

import "time"

type Limits struct {
	MaxActive    int
	MaxKnown     int
	MaxUnknown   int
	MaxProcesses int
	MaxExamples  int
}

func under(n, max int) bool { return max <= 0 || n < max }

func (m *Machine) markTruncated(unknown bool, at time.Time) {
	m.limits.DroppedObservations++
	if unknown {
		if !m.limits.UnknownTruncated {
			m.limits.UnknownTruncated = true
			t := at
			m.limits.UnknownTruncatedSince = &t
		}
		return
	}
	if !m.limits.Truncated {
		m.limits.Truncated = true
		t := at
		m.limits.TruncatedSince = &t
	}
}
