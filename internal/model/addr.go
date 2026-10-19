package model

import "net/netip"

func NormalizeAddr(a netip.Addr) netip.Addr {
	if a.Is4In6() {
		return a.Unmap()
	}
	return a
}

// ScopeFor isolates addresses that only have meaning on one machine (loopback, link-local).
func ScopeFor(a netip.Addr, machineID string) string {
	a = NormalizeAddr(a)
	if a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() {
		return "observer:" + machineID
	}
	return "global"
}

func Family(a netip.Addr) uint8 {
	if NormalizeAddr(a).Is4() {
		return 4
	}
	return 6
}
