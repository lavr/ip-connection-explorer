package procindex

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func fakeProc(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	mk := func(pid, comm string, fds map[string]string) {
		d := filepath.Join(root, pid)
		if err := os.MkdirAll(filepath.Join(d, "fd"), 0o755); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(d, "comm"), []byte(comm+"\n"), 0o644)
		stat := pid + " (" + comm + ") S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 4242 0 0"
		os.WriteFile(filepath.Join(d, "stat"), []byte(stat), 0o644)
		for fd, target := range fds {
			if err := os.Symlink(target, filepath.Join(d, "fd", fd)); err != nil {
				t.Fatal(err)
			}
		}
	}
	mk("123", "postgres", map[string]string{"3": "/dev/null", "4": "socket:[9001]"})
	mk("124", "worker", map[string]string{"5": "socket:[9001]", "6": "socket:[9002]"})
	os.MkdirAll(filepath.Join(root, "self"), 0o755)
	os.WriteFile(filepath.Join(root, "uptime"), []byte("1 1"), 0o644)
	return root
}

func TestBuildIndexFromFakeProc(t *testing.T) {
	at := time.Unix(100, 0)
	idx, st, err := Build(fakeProc(t), at)
	if err != nil {
		t.Fatal(err)
	}
	ps := idx.ByInode[9001]
	if len(ps) != 2 || !idx.At.Equal(at) {
		t.Fatalf("%+v", idx)
	}
	found := false
	for _, p := range ps {
		if p.PID == 123 && p.Comm == "postgres" && p.StartTime == 4242 {
			found = true
		}
	}
	if !found || st.Processes != 2 || st.Sockets != 3 {
		t.Fatalf("%+v %+v", ps, st)
	}
}

func TestBuildIndexTransientMiss(t *testing.T) {
	root := fakeProc(t)
	os.Remove(filepath.Join(root, "124", "comm"))
	_, st, err := Build(root, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if st.TransientMisses != 1 || st.Errors != 0 {
		t.Fatalf("%+v", st)
	}
}

func TestBuildIndexUnreadableRoot(t *testing.T) {
	if _, _, err := Build(filepath.Join(t.TempDir(), "missing"), time.Now()); err == nil {
		t.Fatal("expected error")
	}
}
