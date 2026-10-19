package procindex

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lavr/ip-connection-explorer/internal/flows"
)

type Stats struct {
	Processes       int
	Sockets         int
	TransientMisses int
	Errors          int
}

// Build maps socket inodes to processes by reading <procRoot>/<pid>/fd. Processes that exit
// while being read count as transient misses, not errors.
func Build(procRoot string, at time.Time) (flows.ProcIndex, Stats, error) {
	idx := flows.ProcIndex{At: at, ByInode: map[uint32][]flows.Proc{}}
	var st Stats
	ents, err := os.ReadDir(procRoot)
	if err != nil {
		return idx, st, err
	}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		dir := filepath.Join(procRoot, e.Name())
		inodes, err := socketInodes(filepath.Join(dir, "fd"))
		if err != nil {
			st.count(err)
			continue
		}
		if len(inodes) == 0 {
			continue
		}
		comm, err := os.ReadFile(filepath.Join(dir, "comm"))
		if err != nil {
			st.count(err)
			continue
		}
		p := flows.Proc{PID: pid, Comm: strings.TrimSpace(string(comm)), StartTime: startTime(filepath.Join(dir, "stat"))}
		st.Processes++
		for _, ino := range inodes {
			idx.ByInode[ino] = append(idx.ByInode[ino], p)
			st.Sockets++
		}
	}
	return idx, st, nil
}

func (st *Stats) count(err error) {
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
		st.TransientMisses++
		return
	}
	st.Errors++
}

func socketInodes(fdDir string) ([]uint32, error) {
	fds, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, err
	}
	var out []uint32
	for _, fd := range fds {
		target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
		if err != nil || !strings.HasPrefix(target, "socket:[") {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]"), 10, 32)
		if err == nil {
			out = append(out, uint32(n))
		}
	}
	return out, nil
}

// startTime returns field 22 of /proc/<pid>/stat; the comm field may contain spaces.
func startTime(path string) uint64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0
	}
	fields := strings.Fields(s[i+1:])
	if len(fields) < 20 {
		return 0
	}
	v, _ := strconv.ParseUint(fields[19], 10, 64)
	return v
}
