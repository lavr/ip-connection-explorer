package conntrack

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var (
	// ErrNetlinkModule: opening ctnetlink would make the kernel load nf_conntrack_netlink.
	ErrNetlinkModule = errors.New("nf_conntrack_netlink is not loaded; ipcx does not load kernel modules")
	// ErrNoConntrack: connection tracking is not available in this kernel or namespace.
	ErrNoConntrack = errors.New("connection tracking is not active (no nf_conntrack_count)")
)

// KernelReady checks, without touching netlink, that conntrack is present and that its
// netlink interface is already available (loaded module, or built into the kernel per
// modules.builtin or the kernel config). It returns the current number of tracked entries.
func KernelReady(procRoot, sysRoot, modulesDir string) (int, error) {
	release, _ := os.ReadFile(filepath.Join(procRoot, "sys/kernel/osrelease"))
	return kernelReady(procRoot, sysRoot, modulesDir, "/boot/config-"+strings.TrimSpace(string(release)))
}

func kernelReady(procRoot, sysRoot, modulesDir, bootConfig string) (int, error) {
	b, err := os.ReadFile(filepath.Join(procRoot, "sys/net/netfilter/nf_conntrack_count"))
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrNoConntrack, err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrNoConntrack, err)
	}
	if _, err := os.Stat(filepath.Join(sysRoot, "module", "nf_conntrack_netlink")); err == nil {
		return n, nil
	}
	if builtin(filepath.Join(modulesDir, "modules.builtin"), "nf_conntrack_netlink") {
		return n, nil
	}
	if configBuiltin(filepath.Join(procRoot, "config.gz"), bootConfig, "CONFIG_NF_CT_NETLINK") {
		return n, nil
	}
	return n, ErrNetlinkModule
}

// configBuiltin reports whether option is =y in /proc/config.gz or, failing that, the boot
// config file.
func configBuiltin(procConfigGz, bootConfig, option string) bool {
	var r io.Reader
	if f, err := os.Open(procConfigGz); err == nil {
		defer f.Close()
		if zr, err := gzip.NewReader(f); err == nil {
			r = zr
		}
	}
	if r == nil {
		f, err := os.Open(bootConfig)
		if err != nil {
			return false
		}
		defer f.Close()
		r = f
	}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		if sc.Text() == option+"=y" {
			return true
		}
	}
	return false
}

func builtin(path, module string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.TrimSuffix(filepath.Base(sc.Text()), ".ko") == module {
			return true
		}
	}
	return false
}
