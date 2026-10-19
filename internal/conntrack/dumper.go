//go:build linux

package conntrack

import (
	"context"
	"time"

	"github.com/mdlayher/netlink"
	ct "github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"

	"github.com/lavr/ip-connection-explorer/internal/flows"
)

const (
	msgCTNew        = 0
	msgCTGet        = 1
	maxDumpAttempts = 3
)

// QueryConn is the subset of *netfilter.Conn used for dumps.
type QueryConn interface {
	Query(netlink.Message) ([]netlink.Message, error)
	Close() error
}

type Dumper struct {
	Dial func() (QueryConn, error)
	Now  func() time.Time
}

// Dump issues the request itself instead of using conntrack.Conn.Dump, which does not
// report NLM_F_DUMP_INTR.
func (d *Dumper) Dump(ctx context.Context, attempt, epoch uint64, baseline bool) (flows.DumpResult, DumpStats, error) {
	var st DumpStats
	res := flows.DumpResult{Attempt: attempt, Epoch: epoch, Baseline: baseline}
	req, err := netfilter.MarshalNetlink(netfilter.Header{
		SubsystemID: netfilter.NFSubsysCTNetlink,
		MessageType: msgCTGet,
		Family:      netfilter.ProtoUnspec,
		Flags:       netlink.Request | netlink.Dump,
	}, nil)
	if err != nil {
		return res, st, err
	}
	for i := 0; i < maxDumpAttempts; i++ {
		if err := ctx.Err(); err != nil {
			return res, st, err
		}
		res.Started = d.Now()
		msgs, err := d.query(req)
		if err != nil {
			return res, st, err
		}
		res.Finished = d.Now()
		res.Flows = res.Flows[:0]
		st.DecodeErrors = 0
		interrupted := false
		for _, m := range msgs {
			if m.Header.Flags&netlink.DumpInterrupted != 0 {
				interrupted = true
			}
			var ev ct.Event
			if err := ev.Unmarshal(m); err != nil || ev.Flow == nil || !ev.Flow.TupleOrig.IP.SourceAddress.IsValid() {
				st.DecodeErrors++
				continue
			}
			res.Flows = append(res.Flows, Convert(*ev.Flow))
		}
		if !interrupted {
			res.Complete = true
			return res, st, nil
		}
		st.Interrupted++
	}
	return res, st, nil
}

func (d *Dumper) query(req netlink.Message) ([]netlink.Message, error) {
	c, err := d.Dial()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.Query(req)
}
