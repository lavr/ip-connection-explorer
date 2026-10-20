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

type ifaceAddrs struct {
	up    bool
	addrs []string
}

// Addresses returns the addresses of interfaces that are up. kube-proxy in IPVS mode puts every
// ClusterIP on the kube-ipvs0 dummy, which it keeps down: traffic to those addresses is pod
// traffic balanced by IPVS, not traffic to this host.
func Addresses() ([]netip.Addr, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var all []ifaceAddrs
	for _, ifc := range ifs {
		addrs, err := ifc.Addrs()
		if err != nil {
			return nil, err
		}
		ia := ifaceAddrs{up: ifc.Flags&net.FlagUp != 0}
		for _, a := range addrs {
			ia.addrs = append(ia.addrs, a.String())
		}
		all = append(all, ia)
	}
	return localAddrs(all), nil
}

func localAddrs(ifs []ifaceAddrs) []netip.Addr {
	var out []netip.Addr
	for _, ifc := range ifs {
		if !ifc.up {
			continue
		}
		for _, a := range ifc.addrs {
			if p, err := netip.ParsePrefix(a); err == nil {
				out = append(out, model.NormalizeAddr(p.Addr()))
			}
		}
	}
	return out
}

func readTrim(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
