package conntrack

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestKernelReady(t *testing.T) {
	proc := t.TempDir()
	if _, err := KernelReady(proc); !errors.Is(err, ErrNoConntrack) {
		t.Fatalf("missing conntrack: %v", err)
	}
	os.MkdirAll(filepath.Join(proc, "sys/net/netfilter"), 0o755)
	os.WriteFile(filepath.Join(proc, "sys/net/netfilter/nf_conntrack_count"), []byte("42\n"), 0o644)
	if n, err := KernelReady(proc); err != nil || n != 42 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}
