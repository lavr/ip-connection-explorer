package conntrack

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ErrNoConntrack: connection tracking is not present in this kernel or namespace, so there
// is nothing to observe.
var ErrNoConntrack = errors.New("connection tracking is not active on this host (no nf_conntrack_count); there is nothing to observe")

// KernelReady reports the number of tracked entries, or ErrNoConntrack when conntrack is
// absent. It only reads procfs.
func KernelReady(procRoot string) (int, error) {
	b, err := os.ReadFile(filepath.Join(procRoot, "sys/net/netfilter/nf_conntrack_count"))
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrNoConntrack, err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrNoConntrack, err)
	}
	return n, nil
}
