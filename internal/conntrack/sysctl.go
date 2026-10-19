package conntrack

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func EventsSysctl(procRoot string) (int, error) {
	b, err := os.ReadFile(filepath.Join(procRoot, "sys/net/netfilter/nf_conntrack_events"))
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}
