//go:build linux

package conntrack

import (
	"context"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
	"github.com/ti-mo/netfilter"
)

type fakeQuery struct {
	calls       int
	interrupted int
	closed      int
}

func (f *fakeQuery) Query(req netlink.Message) ([]netlink.Message, error) {
	f.calls++
	m, err := netfilter.MarshalNetlink(netfilter.Header{SubsystemID: netfilter.NFSubsysCTNetlink, MessageType: 0, Family: netfilter.ProtoIPv4}, nil)
	if err != nil {
		return nil, err
	}
	if f.calls <= f.interrupted {
		m.Header.Flags |= netlink.DumpInterrupted
	}
	return []netlink.Message{m}, nil
}

func (f *fakeQuery) Close() error { f.closed++; return nil }

func dumper(q *fakeQuery) *Dumper {
	return &Dumper{Dial: func() (QueryConn, error) { return q, nil }, Now: time.Now}
}

func TestDumpInterruptedRetriesAndMarksIncomplete(t *testing.T) {
	q := &fakeQuery{interrupted: 3}
	res, st, err := dumper(q).Dump(context.Background(), 1, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete || st.Interrupted != 3 || q.calls != 3 {
		t.Fatalf("res=%+v st=%+v calls=%d", res, st, q.calls)
	}
}

func TestDumpRecoversAfterOneInterruption(t *testing.T) {
	q := &fakeQuery{interrupted: 1}
	res, st, err := dumper(q).Dump(context.Background(), 4, 2, true)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Complete || st.Interrupted != 1 || res.Attempt != 4 || res.Epoch != 2 || !res.Baseline || res.Started.IsZero() || res.Finished.Before(res.Started) {
		t.Fatalf("res=%+v st=%+v", res, st)
	}
	if st.DecodeErrors != 1 || len(res.Flows) != 0 || q.closed != 2 {
		t.Fatalf("st=%+v flows=%d closed=%d", st, len(res.Flows), q.closed)
	}
}
