//go:build integration && linux

package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/lavr/ip-connection-explorer/internal/checkpoint"
	"github.com/lavr/ip-connection-explorer/internal/model"
)

const (
	nsA = "ipcx-a"
	nsB = "ipcx-b"
)

func mustRun(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

func nsRun(t *testing.T, ns string, args ...string) string {
	t.Helper()
	return mustRun(t, "ip", append([]string{"netns", "exec", ns}, args...)...)
}

const nftRules = `table inet ipcx {
	chain in { type filter hook input priority 0; ct state established,related accept; }
	chain out { type filter hook output priority 0; ct state new accept; }
}
`

func setupNamespaces(t *testing.T) {
	t.Helper()
	for _, bin := range []string{"ip", "nft"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Fatalf("%s not found: install iproute2 and nftables", bin)
		}
	}
	exec.Command("ip", "netns", "del", nsA).Run()
	exec.Command("ip", "netns", "del", nsB).Run()
	mustRun(t, "ip", "netns", "add", nsA)
	mustRun(t, "ip", "netns", "add", nsB)
	t.Cleanup(func() {
		exec.Command("ip", "netns", "del", nsA).Run()
		exec.Command("ip", "netns", "del", nsB).Run()
	})
	mustRun(t, "ip", "link", "add", "veth-a", "netns", nsA, "type", "veth", "peer", "name", "veth-b", "netns", nsB)
	for ns, v := range map[string][3]string{nsA: {"veth-a", "192.0.2.1/24", "2001:db8::1/64"}, nsB: {"veth-b", "192.0.2.2/24", "2001:db8::2/64"}} {
		nsRun(t, ns, "ip", "addr", "add", v[1], "dev", v[0])
		nsRun(t, ns, "ip", "-6", "addr", "add", v[2], "dev", v[0], "nodad")
		nsRun(t, ns, "ip", "link", "set", v[0], "up")
		nsRun(t, ns, "ip", "link", "set", "lo", "up")
		cmd := exec.Command("ip", "netns", "exec", ns, "nft", "-f", "-")
		cmd.Stdin = strings.NewReader(nftRules)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("nft in %s: %v\n%s", ns, err, out)
		}
	}
	nsRun(t, nsA, "sysctl", "-w", "net.netfilter.nf_conntrack_events=1")
}

func start(t *testing.T, ns string, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("ip", append([]string{"netns", "exec", ns}, args...)...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	return cmd
}

func waitFile(t *testing.T, path string) {
	t.Helper()
	waitUntil(t, fmt.Sprintf("file %s", path), func() bool { _, err := os.Stat(path); return err == nil })
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func latest(dir string) *checkpoint.File {
	m, _ := filepath.Glob(filepath.Join(dir, "*.json.gz"))
	if len(m) != 1 {
		return nil
	}
	f, err := checkpoint.Read(m[0])
	if err != nil {
		return nil
	}
	return f
}

func find(f *checkpoint.File, proto model.Proto, svc string, port uint16) *model.Dependency {
	if f == nil {
		return nil
	}
	for i, d := range f.Dependencies {
		if d.Key.Proto == proto && d.Key.Status == model.RoleKnown && d.Key.Service.String() == svc && d.Key.ServicePort == port {
			return &f.Dependencies[i]
		}
	}
	return nil
}

func has[T comparable](xs []T, x T) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func TestCollectInNamespaces(t *testing.T) {
	ipcx, helper := os.Getenv("IPCX_BIN"), os.Getenv("IPCX_HELPER")
	if ipcx == "" || helper == "" {
		t.Fatal("IPCX_BIN and IPCX_HELPER must point to built binaries")
	}
	t.Log(mustRun(t, "uname", "-r"))
	setupNamespaces(t)
	tmp := t.TempDir()
	state := filepath.Join(tmp, "state")

	start(t, nsB, helper, "tcp-server", ":5432", filepath.Join(tmp, "tcp.ready"))
	start(t, nsB, helper, "udp-server", ":5353", filepath.Join(tmp, "udp.ready"))
	waitFile(t, filepath.Join(tmp, "tcp.ready"))
	waitFile(t, filepath.Join(tmp, "udp.ready"))

	start(t, nsA, helper, "hold", "192.0.2.2:5432", filepath.Join(tmp, "hold.ready"))
	waitFile(t, filepath.Join(tmp, "hold.ready"))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	collector := exec.CommandContext(ctx, "ip", "netns", "exec", nsA, ipcx, "collect",
		"--duration", "1h", "--checkpoint", "1s", "--dump-every", "2s", "--snapshot-every", "1s", "--state-dir", state)
	collector.Stderr = os.Stderr
	if err := collector.Start(); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "baseline checkpoint with the long-lived flow", func() bool {
		return find(latest(state), model.ProtoTCP, "192.0.2.2", 5432) != nil
	})

	for i := 0; i < 3; i++ {
		nsRun(t, nsA, helper, "tcp-client", "192.0.2.2:5432")
	}
	nsRun(t, nsA, helper, "udp-sendto", "192.0.2.2:5353")
	nsRun(t, nsA, helper, "tcp-client", "[2001:db8::2]:5432")

	waitUntil(t, "event, udp and ipv6 dependencies", func() bool {
		f := latest(state)
		d := find(f, model.ProtoTCP, "192.0.2.2", 5432)
		return d != nil && has(d.Sources, model.SourceEvent) && find(f, model.ProtoTCP, "2001:db8::2", 5432) != nil &&
			find(f, model.ProtoUDP, "192.0.2.2", 5353) != nil
	})

	if err := collector.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := collector.Wait(); err != nil {
		t.Fatalf("collector exit: %v", err)
	}

	f := latest(state)
	tcp := find(f, model.ProtoTCP, "192.0.2.2", 5432)
	if !has(tcp.Sources, model.SourceBaseline) || !has(tcp.Sources, model.SourceEvent) {
		t.Errorf("tcp sources %v", tcp.Sources)
	}
	if tcp.FlowsObserved < 4 || tcp.Direction != model.DirOutbound {
		t.Errorf("tcp flows=%d direction=%v", tcp.FlowsObserved, tcp.Direction)
	}
	comms := map[string]bool{}
	for _, p := range tcp.Processes {
		comms[p.Comm] = true
	}
	if !comms["helpers"] {
		t.Errorf("helper process not attributed: %+v", tcp.Processes)
	}
	for _, d := range f.Dependencies {
		if d.Key.Proto == model.ProtoUDP && d.Key.Status == model.RoleKnown && d.Key.Service.String() == "192.0.2.1" {
			t.Errorf("udp client became a service: %+v", d.Key)
		}
	}
	if f.Coverage.HistoryIncomplete {
		t.Errorf("unexpected incomplete history: %+v", f.Coverage)
	}
	if f.Coverage.EventsSysctl != 1 {
		t.Errorf("events sysctl %d", f.Coverage.EventsSysctl)
	}
}

const nsPod = "ipcx-pod"

// TestSNATRecordedFromHostAddress routes a "pod" namespace through nsA, which masquerades it
// behind 192.0.2.1, the way a Kubernetes node or a Docker host does.
func TestSNATRecordedFromHostAddress(t *testing.T) {
	ipcx, helper := os.Getenv("IPCX_BIN"), os.Getenv("IPCX_HELPER")
	if ipcx == "" || helper == "" {
		t.Fatal("IPCX_BIN and IPCX_HELPER must point to built binaries")
	}
	setupNamespaces(t)
	exec.Command("ip", "netns", "del", nsPod).Run()
	mustRun(t, "ip", "netns", "add", nsPod)
	t.Cleanup(func() { exec.Command("ip", "netns", "del", nsPod).Run() })
	mustRun(t, "ip", "link", "add", "veth-pod", "netns", nsPod, "type", "veth", "peer", "name", "veth-node", "netns", nsA)
	nsRun(t, nsPod, "ip", "addr", "add", "10.233.70.5/24", "dev", "veth-pod")
	nsRun(t, nsPod, "ip", "link", "set", "veth-pod", "up")
	nsRun(t, nsPod, "ip", "route", "add", "default", "via", "10.233.70.1")
	nsRun(t, nsA, "ip", "addr", "add", "10.233.70.1/24", "dev", "veth-node")
	nsRun(t, nsA, "ip", "link", "set", "veth-node", "up")
	nsRun(t, nsA, "sysctl", "-w", "net.ipv4.ip_forward=1")
	cmd := exec.Command("ip", "netns", "exec", nsA, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(`table ip ipcxnat {
	chain post { type nat hook postrouting priority 100; oifname "veth-a" masquerade; }
}
`)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft nat: %v\n%s", err, out)
	}

	tmp := t.TempDir()
	state := filepath.Join(tmp, "state")
	start(t, nsB, helper, "tcp-server", ":5432", filepath.Join(tmp, "tcp.ready"))
	waitFile(t, filepath.Join(tmp, "tcp.ready"))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	collector := exec.CommandContext(ctx, "ip", "netns", "exec", nsA, ipcx, "collect",
		"--duration", "1h", "--checkpoint", "1s", "--dump-every", "2s", "--snapshot-every", "1s", "--state-dir", state)
	collector.Stderr = os.Stderr
	if err := collector.Start(); err != nil {
		t.Fatal(err)
	}
	waitFile(t, filepath.Join(state, ".ipcx.lock"))
	waitUntil(t, "first checkpoint", func() bool { return latest(state) != nil })
	nsRun(t, nsPod, helper, "tcp-client", "192.0.2.2:5432")
	var d *model.Dependency
	waitUntil(t, "masqueraded dependency", func() bool {
		d = find(latest(state), model.ProtoTCP, "192.0.2.2", 5432)
		return d != nil
	})
	collector.Process.Signal(syscall.SIGTERM)
	collector.Wait()

	if d.Key.Initiator.String() != "192.0.2.1" || d.Direction != model.DirOutbound || !has(d.Evidence, model.EvidenceSNAT) {
		t.Errorf("key=%+v direction=%v evidence=%v", d.Key, d.Direction, d.Evidence)
	}
	if len(d.Examples) == 0 || d.Examples[0].Orig.Src.Addr.String() != "10.233.70.5" {
		t.Errorf("examples lost the pod address: %+v", d.Examples)
	}
}
