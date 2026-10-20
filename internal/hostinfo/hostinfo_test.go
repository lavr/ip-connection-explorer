package hostinfo

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestHostinfoFromFakeRoots(t *testing.T) {
	proc, etc := t.TempDir(), t.TempDir()
	write(t, etc, "machine-id", "abc123\n")
	write(t, proc, "sys/kernel/random/boot_id", "boot-1\n")
	write(t, proc, "sys/kernel/osrelease", "6.8.0-test\n")
	write(t, proc, "sys/net/ipv4/ip_local_port_range", "32768\t60999\n")
	info, err := Collect(proc, etc)
	if err != nil {
		t.Fatal(err)
	}
	if info.MachineID != "abc123" || info.BootID != "boot-1" || info.Kernel != "6.8.0-test" || info.PortRangeLow != 32768 || info.PortRangeHigh != 60999 || info.Hostname == "" {
		t.Fatalf("%+v", info)
	}
}

func TestHostinfoMissingMachineID(t *testing.T) {
	if _, err := Collect(t.TempDir(), t.TempDir()); err == nil {
		t.Fatal("expected error")
	}
}

func TestAddressesNormalized(t *testing.T) {
	as, err := Addresses()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range as {
		if a.Is4In6() {
			t.Fatalf("not normalized: %v", a)
		}
	}
}

func TestLocalAddrsSkipDownInterfaces(t *testing.T) {
	ifs := []ifaceAddrs{
		{up: true, addrs: []string{"127.0.0.1/8", "::1/128"}},
		{up: true, addrs: []string{"192.0.2.10/24", "fe80::1/64"}},
		{up: false, addrs: []string{"198.51.100.7/32", "198.51.100.8/32"}},
		{up: true, addrs: []string{"203.0.113.1/24"}},
	}
	got := localAddrs(ifs)
	want := []string{"127.0.0.1", "::1", "192.0.2.10", "fe80::1", "203.0.113.1"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}
