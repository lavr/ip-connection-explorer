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
