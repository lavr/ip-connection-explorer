package conntrack

import (
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func fakeRoots(t *testing.T, module, builtin, count bool) (proc, sys, mods string) {
	t.Helper()
	proc, sys, mods = t.TempDir(), t.TempDir(), t.TempDir()
	if module {
		os.MkdirAll(filepath.Join(sys, "module", "nf_conntrack_netlink"), 0o755)
	}
	if builtin {
		os.WriteFile(filepath.Join(mods, "modules.builtin"), []byte("kernel/net/netfilter/nf_conntrack_netlink.ko\n"), 0o644)
	}
	if count {
		os.MkdirAll(filepath.Join(proc, "sys/net/netfilter"), 0o755)
		os.WriteFile(filepath.Join(proc, "sys/net/netfilter/nf_conntrack_count"), []byte("42\n"), 0o644)
	}
	return
}

func TestKernelReady(t *testing.T) {
	cases := []struct {
		name                   string
		module, builtin, count bool
		want                   error
	}{
		{"loaded", true, false, true, nil},
		{"builtin", false, true, true, nil},
		{"netlink module missing", false, false, true, ErrNetlinkModule},
		{"conntrack missing", true, false, false, ErrNoConntrack},
	}
	for _, c := range cases {
		proc, sys, mods := fakeRoots(t, c.module, c.builtin, c.count)
		n, err := KernelReady(proc, sys, mods)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err=%v want %v", c.name, err, c.want)
		}
		if c.want == nil && n != 42 {
			t.Errorf("%s: count=%d", c.name, n)
		}
	}
}

func TestKernelReadyFromConfig(t *testing.T) {
	for _, c := range []struct {
		line string
		want error
	}{
		{"CONFIG_NF_CT_NETLINK=y", nil},
		{"CONFIG_NF_CT_NETLINK=m", ErrNetlinkModule},
	} {
		proc, sys, mods := fakeRoots(t, false, false, true)
		boot := t.TempDir()
		os.WriteFile(filepath.Join(boot, "config-test"), []byte("CONFIG_X=y\n"+c.line+"\n"), 0o644)
		if _, err := kernelReady(proc, sys, mods, filepath.Join(boot, "config-test")); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", c.line, err)
		}
	}
}

func TestKernelReadyFromProcConfigGz(t *testing.T) {
	proc, sys, mods := fakeRoots(t, false, false, true)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte("CONFIG_NF_CT_NETLINK=y\n"))
	zw.Close()
	os.WriteFile(filepath.Join(proc, "config.gz"), buf.Bytes(), 0o644)
	if _, err := kernelReady(proc, sys, mods, "/nonexistent"); err != nil {
		t.Fatal(err)
	}
}
