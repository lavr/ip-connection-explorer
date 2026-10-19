package main

import (
	"testing"
	"time"
)

func TestParseDuration(t *testing.T) {
	ok := map[string]time.Duration{
		"7d":    168 * time.Hour,
		"36h":   36 * time.Hour,
		"1d12h": 36 * time.Hour,
		"90s":   90 * time.Second,
	}
	for in, want := range ok {
		got, err := parseDuration(in)
		if err != nil || got != want {
			t.Errorf("%q: got %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "-1d", "0", "0d", "xd", "d"} {
		if _, err := parseDuration(in); err == nil {
			t.Errorf("%q: expected error", in)
		}
	}
}
