package hostinfo

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/lavr/ip-connection-explorer/internal/model"
)

type Info struct {
	Hostname      string
	MachineID     string
	BootID        string
	Kernel        string
	PortRangeLow  uint16
	PortRangeHigh uint16
}

func Collect(procRoot, etcRoot string) (Info, error) {
	var info Info
	var err error
	if info.Hostname, err = os.Hostname(); err != nil {
		return info, err
	}
	if info.MachineID, err = readTrim(filepath.Join(etcRoot, "machine-id")); err != nil {
		return info, err
	}
	if info.BootID, err = readTrim(filepath.Join(procRoot, "sys/kernel/random/boot_id")); err != nil {
		return info, err
	}
	if info.Kernel, err = readTrim(filepath.Join(procRoot, "sys/kernel/osrelease")); err != nil {
		return info, err
	}
	pr, err := readTrim(filepath.Join(procRoot, "sys/net/ipv4/ip_local_port_range"))
	if err != nil {
		return info, err
	}
	f := strings.Fields(pr)
	if len(f) != 2 {
		return info, fmt.Errorf("unexpected ip_local_port_range %q", pr)
	}
	lo, err1 := strconv.ParseUint(f[0], 10, 16)
	hi, err2 := strconv.ParseUint(f[1], 10, 16)
	if err1 != nil || err2 != nil {
		return info, fmt.Errorf("unexpected ip_local_port_range %q", pr)
	}
	info.PortRangeLow, info.PortRangeHigh = uint16(lo), uint16(hi)
	return info, nil
}

func KernelRelease(procRoot string) (string, error) {
	return readTrim(filepath.Join(procRoot, "sys/kernel/osrelease"))
}

func Addresses() ([]netip.Addr, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, model.NormalizeAddr(p.Addr()))
		}
	}
	return out, nil
}

func readTrim(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
