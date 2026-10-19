package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// parseDuration accepts time.ParseDuration syntax plus a leading day count, e.g. "7d" or "1d12h".
func parseDuration(s string) (time.Duration, error) {
	var total time.Duration
	rest := s
	if i := strings.IndexByte(s, 'd'); i >= 0 {
		days, err := strconv.ParseUint(s[:i], 10, 32)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		total = time.Duration(days) * 24 * time.Hour
		rest = s[i+1:]
	}
	if rest != "" {
		d, err := time.ParseDuration(rest)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		total += d
	}
	if s == "" || total <= 0 {
		return 0, fmt.Errorf("duration must be positive: %q", s)
	}
	return total, nil
}
