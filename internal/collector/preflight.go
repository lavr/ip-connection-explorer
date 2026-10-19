package collector

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

type PreflightResult struct {
	Name   string
	OK     bool
	Fatal  bool
	Detail string
}

// Preflight checks the operations collect needs, per component. Conntrack and state directory
// failures are fatal; socket and process failures only disable attribution.
func Preflight(cfg Config, src Sources) ([]PreflightResult, bool) {
	var res []PreflightResult
	ok := true
	add := func(name string, err error, fatal bool, detail string) {
		r := PreflightResult{Name: name, OK: err == nil, Detail: detail}
		if err != nil {
			r.Fatal = fatal
			r.Detail = err.Error()
			if fatal {
				ok = false
			}
		}
		res = append(res, r)
	}
	now := time.Now().UTC()

	stateDetail := cfg.StateDir
	stateErr := checkWritable(cfg.StateDir)
	if errors.Is(stateErr, fs.ErrNotExist) {
		stateDetail += " (will be created)"
		stateErr = checkWritable(filepath.Dir(cfg.StateDir))
	}
	add("state_dir", stateErr, true, stateDetail)

	_, err := src.Host()
	add("host_info", err, true, "machine-id, boot_id, kernel, port range")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	dump, _, err := src.Dump(ctx, 0, 0, false)
	cancel()
	add("conntrack_dump", err, true, fmt.Sprintf("%d entries", len(dump.Flows)))

	sub, err := src.Subscribe(0)
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = sub.Close(ctx)
		cancel()
	}
	add("conntrack_events", err, true, "subscription to NEW, UPDATE, DESTROY")

	v, err := src.EventsSysctl()
	switch {
	case err != nil:
		add("events_sysctl", err, false, "")
	case v == 0 && !cfg.AllowNoEvents:
		add("events_sysctl", fmt.Errorf("nf_conntrack_events=0: the kernel sends no events; rerun with --allow-no-events to collect from periodic dumps only"), true, "")
	default:
		add("events_sysctl", nil, false, fmt.Sprintf("nf_conntrack_events=%d", v))
	}

	snap, err := src.Sockets(now)
	add("sock_diag", err, false, fmt.Sprintf("%d sockets", len(snap.Sockets)))

	_, st, err := src.Procs(now)
	if err == nil && st.Errors > 0 && st.Processes == 0 {
		err = fmt.Errorf("no process readable (%d errors)", st.Errors)
	}
	add("proc_fd", err, false, fmt.Sprintf("%d processes with sockets", st.Processes))
	return res, ok
}

func checkWritable(dir string) error {
	f, err := os.CreateTemp(dir, ".ipcx-preflight-*")
	if err != nil {
		return err
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}
