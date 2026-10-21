# ipcx

`ipcx` (ip-connection-explorer) records which network dependencies a Linux host actually has,
so that firewall rules can be requested before the host is moved to another network segment.

Hosts that share one L2 segment talk to each other without crossing a firewall, so nobody has
rules or logs for that traffic. Configuration files and documentation miss rare clients:
weekly jobs, backups, OAuth callbacks. `ipcx` watches the host itself for days, keeps a compact
map of who talks to whom, and turns maps from many hosts into one reviewable table.

It does not capture packets, does not inspect payload, does not generate firewall rules and
does not change kernel settings.

## How it works

`ipcx collect` runs on the observed host and reads four sources:

- **conntrack events** (NEW, UPDATE, DESTROY) through netlink, for connections that start
  while it runs;
- **conntrack dumps**: one baseline dump at start, then a periodic dump. Connections that were
  open before the collector started (database pools, message brokers, LDAP) never produce a new
  event, and with `nf_conntrack_events=2` a flow created before any listener existed may never
  produce events at all, so the periodic dump is required;
- **socket snapshots** through sock_diag, to confirm which side listens;
- **a process index** from `/proc/<pid>/fd`, to name the local process of a connection.

Every flow gets a role (who initiates, which side is the service) from the evidence it has,
with a confidence level. Flows are aggregated into dependencies such as
`192.0.2.10 -> 198.51.100.5:443/tcp`, and the aggregate is written to a checkpoint file every
few minutes. Design details: [docs/design.md](docs/design.md).

## How it differs from other tools

`ipcx` answers one question: which rules does this host need once a firewall stands between it
and its peers. It sees both directions, including inbound clients that run no agent, decides
which side is the server, and produces a reviewable table. It needs no eBPF, works on kernel 5.4,
and runs for a bounded window; a beta [Prometheus exporter](#prometheus-exporter-beta) keeps the
same matrix permanently.

| Tool | Output | Inbound clients | Knows the server side | Needs |
|---|---|---|---|---|
| `ipcx` | report for a window, Prometheus (beta) | yes | yes | conntrack |
| [coroot-node-agent](https://github.com/coroot/coroot-node-agent) | Prometheus | no | outbound only | eBPF, 4.16+ |
| [Beyla](https://grafana.com/docs/beyla/latest/network/) | Prometheus | yes | no | eBPF, 5.8+ |
| [conntrack_exporter](https://github.com/hiveco/conntrack_exporter) | Prometheus | yes | no | conntrack |
| [Caretta](https://github.com/groundcover-com/caretta), [Hubble](https://github.com/cilium/hubble), [Retina](https://github.com/microsoft/retina), [NetObserv](https://github.com/netobserv/netobserv-ebpf-agent) | service map | yes | partly | Kubernetes |
| Telegraf [`conntrack`](https://docs.influxdata.com/telegraf/v1/input-plugins/conntrack/), [`netstat`](https://docs.influxdata.com/telegraf/v1/input-plugins/netstat/) | totals | no | no | nothing |

coroot-node-agent counts outbound connects per destination; inbound clients appear only if they
run the agent too. Beyla counts bytes per flow in packet direction, so a reply carries the
client's ephemeral port. conntrack_exporter shows connections open at scrape time and has no
local address.

For the list of rules to request before a move, use `ipcx`. For permanent monitoring, try its
beta exporter, or one of the agents above if you need bytes, latency or process names.

## Install

Download the archive for your architecture from the
[releases page](https://github.com/lavr/ip-connection-explorer/releases), check it and unpack:

```sh
sha256sum --check --ignore-missing checksums.txt
tar -xzf ipcx_<version>_linux_amd64.tar.gz
sudo install -m 0755 ipcx /usr/local/bin/ipcx
```

The binary is static and has no runtime dependencies. To build from source you need Go 1.24 or
newer and `make`: `make build` produces `bin/ipcx`. `merge` and `report` also run on macOS;
`collect` needs Linux.

## Quick start

On every host you want to map:

```sh
sudo ipcx collect --check
sudo ipcx collect --duration 7d --state-dir /var/lib/ipcx
```

`--check` runs the preflight and prints one line per component:

```
ok    state_dir        /var/lib/ipcx
ok    host_info        machine-id, boot_id, kernel, port range
ok    conntrack_kernel 742 tracked entries
ok    conntrack_dump   742 entries
ok    conntrack_events subscription to NEW, UPDATE, DESTROY
ok    events_sysctl    nf_conntrack_events=2
ok    sock_diag        376 sockets
ok    proc_fd          41 processes with sockets
```

The state directory is created if it does not exist. `collect` stops after `--duration` or on
SIGTERM or SIGINT and writes a final checkpoint
`<hostname>-<run_id>.json.gz` into the state directory. Copy the files to one place and:

```sh
ipcx merge host-a-*.json.gz host-b-*.json.gz -o all.json.gz
ipcx report all.json.gz --format csv > dependencies.csv
```

Run a week rather than a day: weekly jobs and backups are exactly what a short window misses.

Checkpoints and raw journals contain host names, machine IDs, addresses and process names.
Remove or replace them before attaching a file to a public issue.

### Example systemd unit

```ini
[Unit]
Description=ipcx network dependency collector
After=network-online.target

[Service]
ExecStart=/usr/local/bin/ipcx collect --duration 7d --state-dir /var/lib/ipcx
Nice=10
Restart=no

[Install]
WantedBy=multi-user.target
```

A CPU quota can slow the event reader enough to lose events; if you set one, watch the gaps in
the report.

## Commands

| Command | Flags |
|---|---|
| `ipcx collect` | `--duration 7d` (`0` runs until stopped), `--state-dir /var/lib/ipcx`, `--checkpoint 2m`, `--dump-every 5m`, `--snapshot-every 60s`, `--raw`, `--nat-view host`, `--go-memory-limit SIZE`, `--max-active 200000`, `--max-known 100000`, `--max-unknown 50000`, `--allow-no-events`, `--check`, `--prometheus-exporter.listen ADDR`, `--prometheus-exporter.path /metrics`, `--prometheus-exporter.ttl 24h`, `--prometheus-exporter.max-series 10000` |
| `ipcx merge FILE... -o OUT` | |
| `ipcx report FILE` | `--format csv\|json`, `--role known\|unknown\|all`, `--min-confidence low\|medium\|high`, `--include-hidden` |

Exit codes: `0` success, `1` runtime failure, `2` usage error, `3` preflight failed,
`4` state directory locked by another collector.

`--cpuprofile FILE` and `--memprofile FILE` write Go profiles for debugging. The files are
created with mode 0600 and an existing path is never overwritten; put them in a private
directory. The heap profile is written after collection has stopped, so it does not show the
peak live heap.

`--raw` also keeps a rotated journal of events and dump markers for later analysis:
`raw-<run_id>-*.jsonl.gz` plus `raw-<run_id>.json` with the retained time span. The limits of
32 MiB per file and 256 MiB per run are counted before compression and enforced when a file is
rotated; journals of earlier runs are not removed.

`report` defaults: `--format csv`, `--role all`, `--min-confidence low`, hidden rows off. The JSON
format applies the same filters.

## Prometheus exporter (beta)

`--prometheus-exporter.listen ADDR` serves the connection matrix over HTTP for Prometheus or
VictoriaMetrics. The flags, metric names and labels may still change.

```sh
ipcx collect --prometheus-exporter.listen 10.0.0.5:9917
```

Without an explicit `--duration` the collector runs until stopped and writes no checkpoint: the
state directory holds only the lock file, and `--raw` is refused. With `--duration` (for
example `7d`, or `0` for no end) checkpoints are written as usual and the exporter runs beside
them. The listener has no TLS and no authentication: bind it to an internal address or close
the port with a firewall. The scrape connection itself appears in the matrix.

| Metric | Type | Meaning |
|---|---|---|
| `ipcx_connections_finished_total` | counter | connection lifetimes that ended, by their final role |
| `ipcx_connections_active` | gauge | connections open at the last sample, taken every `--snapshot-every` |
| `ipcx_exporter_ready` | gauge | `1` once the first conntrack dump is applied |
| `ipcx_exporter_series`, `ipcx_exporter_series_rejected_total` | gauge, counter | label sets in the table; admissions refused because it was full |
| `ipcx_flows_active`, `ipcx_flows_rejected_total` | gauge, counter | conntrack entries tracked; observations dropped at `--max-active` |
| `ipcx_gaps_total`, `ipcx_gap_open{kind}` | counter, gauge | periods when connections could be missed |
| `ipcx_last_checkpoint_timestamp_seconds`, `ipcx_build_info` | gauge | |

Connection labels:

- `role`: `known`, `unknown` or `conflict`. For `known`, `src_ip` is the client and
  `dst_ip:dst_port` the service. Otherwise they follow the first packet conntrack saw, which
  is not proof of who the client is.
- `direction`: relative to this host, as in the report. `forwarded` means neither end of the
  original direction is a local address.
- `proto`, `src_ip`, `dst_ip`, `dst_port`. There is no source port and no process. A local
  ephemeral port is shown as `0`, and so is the port of ICMP.

A connection is counted in `finished_total` when it ends, so a pool that stays open for weeks
shows only in `active`, and a single short connection may never be seen in `active`. The matrix
is the set of series the exporter currently holds, whatever their values:

```promql
count by (instance, src_ip, dst_ip, dst_port, proto) (ipcx_connections_finished_total)
```

A pair stays in it until it has been idle for the TTL, so this is "seen within about the TTL",
not an exact window. Check `ipcx_exporter_ready`, `ipcx_exporter_series_rejected_total` and
`ipcx_gaps_total` before trusting that a pair is absent.
Labels use the same view as the report: a connection masqueraded behind a host address is
shown from that address (see NAT below), and behind DNAT the destination is the original one,
not necessarily the final backend.
Counts from several hosts describe what each host observed; do not add them up as unique
connections.

A label set that has seen no connection for `--prometheus-exporter.ttl` leaves the output; if
it comes back, its counter starts again from zero. The table holds at most
`--prometheus-exporter.max-series` label sets (two series each); further new ones are refused
and counted, existing ones keep updating. Removed series stay in the TSDB until its retention.

## Report columns

One row per dependency and observer run. Both ends of a connection report it, so the same
dependency usually appears twice: outbound on the client, inbound on the server.

| Column | Meaning |
|---|---|
| `role_status` | `known`, `unknown` or `conflict` |
| `scope` | `global`, or `observer:<machine-id>` for loopback and link-local addresses |
| `proto` | `tcp`, `udp`, `icmp`, `icmpv6` |
| `initiator`, `service`, `service_port` | filled for known roles |
| `icmp_type`, `icmp_code` | ICMP instead of a port |
| `endpoint_a`, `port_a`, `endpoint_b`, `port_b` | both ports in the original direction, for unknown and conflict rows; `0` means a local port omitted because it falls in the host's ephemeral range and nothing listens on it |
| `observer`, `run_id` | which host and run saw it |
| `direction` | relative to the observer: `outbound`, `inbound`, `local`, `forwarded`, `unresolved` |
| `confidence`, `evidence` | how the role was decided, see below |
| `processes` | local processes, `comm@address[:port]` |
| `first_seen`, `last_seen` | when the collector observed it, not when the connection started |
| `flows_observed`, `flows_estimated` | connection lifetimes seen; estimated after gaps or restarts |
| `ever_reply_seen` | a reply was seen at least once |
| `coverage_status` | `complete`; `incomplete` (a gap, events disabled, or the run had not finished); `truncated` (a limit was hit); `incomplete+truncated` |

Loopback and link-local, forwarded and unresolved (NAT other than plain source NAT) rows are
hidden unless
`--include-hidden` is given.
`report` prints a summary to stderr with what was hidden and which runs are incomplete.

## Confidence and evidence

| Evidence | Meaning |
|---|---|
| `conntrack_new` | a live conntrack NEW event in TCP state `SYN_SENT` |
| `conntrack_original` | the connection was already open, or the start was not observed; the original direction is assumed |
| `listen` | a listening socket on the service side confirms it |
| `listen_contradicts` | the supposed client side listens on that port: role is `conflict` |
| `port_range` | UDP from a local ephemeral port: a weak hint |
| `udp_bound` | UDP from outside to a bound, non-ephemeral local port: a weak hint that it is a server |
| `conntrack_snat` | the connection left through source NAT to a host address and is recorded from that address; the original source is in the example tuples |
| `none` | nothing decides the role: `unknown` |

`high` is confidence in the inferred role, not a promise that a firewall rule derived from it is
correct. Review the table before you send it anywhere.

## Limitations

- **Gaps are permanent.** If the event stream breaks (for example `ENOBUFS`), the collector
  resubscribes and resynchronises with a full dump, but a connection that opened and closed
  inside the gap is lost. The checkpoint records every gap and marks the history incomplete.
- **`nf_conntrack_events=0`** means the kernel sends no events. `collect` refuses to run unless
  `--allow-no-events` is given, and then sees only what the periodic dumps catch.
- **Only flows that conntrack tracks** are seen. A host without stateful firewall rules may not
  track connections at all: `--check` fails when conntrack is absent and warns when it has no
  entries. `ipcx` never adds rules or enables tracking.
- **Kernel modules.** Like `ss` and `conntrack`, opening the netlink interfaces can make the
  kernel autoload `nf_conntrack_netlink`, `inet_diag`, `tcp_diag` and `udp_diag`. They only
  expose interfaces; they do not change packet handling.
- **UDP roles are often unknown.** A UDP socket bound without a peer is not evidence of a
  server, because a client calling `sendto` looks the same. Such flows keep both ports.
- **IPv6 wildcard listeners** (`[::]:port`) may or may not accept IPv4; for IPv4 traffic they
  add `listen` evidence but never raise confidence.
- **Current network namespace only.** Containers in their own namespaces are not observed.
- **Crash window.** Periodic checkpoints limit what a crash loses: data after the last
  checkpoint is gone. The checkpoint file is synced before it replaces the previous one, but
  the directory is not, so on power loss the newest replacement may not survive.
- **`--go-memory-limit`** is a soft target for the Go garbage collector, not a cap on memory.
  The hard bounds are `--max-active` (which also caps tombstones of closed flows),
  `--max-known` and `--max-unknown`; when one is hit the report says `truncated`.
- **`forwarded` does not mean IP forwarding.** Any flow with no local endpoint lands there,
  including broadcasts received from neighbours on the same L2 segment (DHCP, discovery
  protocols). These rows are hidden by default.
- **Kubernetes nodes.** Pod-to-pod and pod-to-ClusterIP traffic routed by the node is
  `forwarded`. Host addresses are taken only from interfaces that are up, so the ClusterIPs that
  kube-proxy in IPVS mode keeps on the down `kube-ipvs0` dummy do not count as the node's own.
  Traffic between the node and its own pods (kubelet probes from the bridge address) is still
  shown as `outbound`, and so is pod traffic masqueraded to the outside (see NAT above).
- **NAT.** A connection from a non-local source that this host masquerades behind one of its
  own addresses (Kubernetes pods or Docker containers reaching outside, for example) is
  recorded from that host address: `outbound`, with `conntrack_snat` evidence. That is the
  source a firewall beyond the host sees, and it keeps short-lived pod addresses out of the
  table. It applies only when conntrack marks the entry as source-NATed, the destination is
  unchanged and neither original endpoint is local; anything with DNAT (ClusterIP, NodePort)
  keeps the original view, and its direction follows the usual rules. `--nat-view original`
  records every connection from its original source, as before 0.3. Checkpoints record the
  view; `merge` compares roles across views on the original tuple, so mixing them is not a
  conflict. Checkpoints from 0.3 use schema 2, which 0.2 cannot read: upgrade `merge` and
  `report` first, they still read the old files.
- Absence of traffic during the run is not proof that a dependency does not exist.

## Tested on

- Linux 6.17 (GitHub `ubuntu-24.04` runner, the integration test in CI).
- Linux 7.2 (integration tests in a privileged container: network namespaces, nftables,
  IPv4 and IPv6).

Older kernels, including 5.4, are expected to work but are not listed until tested.

## Agent skill

A skill for Claude Code and Codex is published from this repository as a plugin. It teaches the
agent to run the preflight and a collection, read the report and prepare a firewall request,
and to ask before touching a host:

```sh
# Claude Code
claude plugin marketplace add lavr/ip-connection-explorer
claude plugin install ipcx@ipcx

# Codex
codex plugin marketplace add lavr/ip-connection-explorer
codex plugin add ipcx@ipcx
```

Install it by one route per agent, not both.

## Development

Contributor and agent guidance: [AGENTS.md](AGENTS.md).

```sh
make test               # unit tests
make load               # open-loop collector load test (10k events/s)
make test-linux         # unit tests in a Linux container (netlink adapters)
make integration-docker # namespace integration test in a privileged container
make integration        # the same on a Linux host, with sudo
```

### Releases

Releases are cut from `main` with `release.sh`:

```sh
./release.sh status              # latest release tag
./release.sh app 0.1.1 --dry-run # preview an explicit release
./release.sh app patch           # later: patch, minor, major or X.Y.Z
```

The script tags the current `main` (tags are plain `X.Y.Z`) and pushes it. The tag starts the
release workflow: the tests run again, GoReleaser builds a snapshot that is smoke tested, and
only then publishes the `linux/amd64` and `linux/arm64` archives, `checksums.txt` and release
notes generated by GitHub.

## License

MIT, see [LICENSE](LICENSE).
