package report

import (
	"encoding/csv"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/lavr/ip-connection-explorer/internal/model"
)

var columns = []string{
	"role_status", "scope", "proto", "initiator", "service", "service_port", "icmp_type", "icmp_code",
	"endpoint_a", "port_a", "endpoint_b", "port_b", "observer", "run_id", "direction", "confidence",
	"evidence", "processes", "first_seen", "last_seen", "flows_observed", "flows_estimated",
	"ever_reply_seen", "coverage_status",
}

func writeCSV(w io.Writer, deps []model.Dependency, status map[string]string) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(columns); err != nil {
		return err
	}
	for _, d := range deps {
		if err := cw.Write(row(d, status)); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func row(d model.Dependency, status map[string]string) []string {
	k := d.Key
	r := make([]string, len(columns))
	r[0] = k.Status.String()
	r[1] = k.Scope
	r[2] = k.Proto.String()
	if k.Status == model.RoleKnown {
		r[3], r[4] = k.Initiator.String(), k.Service.String()
		if k.Proto.IsICMP() {
			r[6], r[7] = strconv.Itoa(int(k.ICMPType)), strconv.Itoa(int(k.ICMPCode))
		} else {
			r[5] = strconv.Itoa(int(k.ServicePort))
		}
	}
	if k.A.Addr.IsValid() {
		r[8], r[9] = k.A.Addr.String(), strconv.Itoa(int(k.A.Port))
		r[10], r[11] = k.B.Addr.String(), strconv.Itoa(int(k.B.Port))
	}
	r[12] = d.Observer.Hostname
	r[13] = d.Observer.RunID
	r[14] = d.Direction.String()
	r[15] = d.Confidence.String()
	ev := make([]string, len(d.Evidence))
	for i, e := range d.Evidence {
		ev[i] = e.String()
	}
	r[16] = strings.Join(ev, "+")
	procs := make([]string, len(d.Processes))
	for i, p := range d.Processes {
		where := p.Endpoint.Addr.String()
		if p.Endpoint.Port != 0 {
			where = p.Endpoint.String()
		}
		procs[i] = p.Comm + "@" + where
	}
	r[17] = strings.Join(procs, ";")
	r[18] = d.FirstSeen.UTC().Format(time.RFC3339)
	r[19] = d.LastSeen.UTC().Format(time.RFC3339)
	r[20] = strconv.FormatUint(d.FlowsObserved, 10)
	r[21] = strconv.FormatBool(d.FlowsEstimated)
	r[22] = strconv.FormatBool(d.EverReplySeen)
	r[23] = status[d.Observer.RunID]
	if r[23] == "" {
		r[23] = "unknown"
	}
	return r
}
