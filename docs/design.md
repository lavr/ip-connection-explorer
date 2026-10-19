# ipcx design

Status: draft v1, 2026-10-19.

## Purpose

`ipcx` (ip-connection-explorer) records which network dependencies a Linux host actually has,
so that firewall rules can be requested before the host is moved to another network segment.

Typical case: hosts share one L2 segment, so their traffic to each other never crosses a
firewall and no rules exist for it. After the hosts are split into separate segments, every
such flow needs a rule. Configuration files and documentation miss rare clients (weekly jobs,
backups, OAuth callbacks), so the map has to be observed on the hosts themselves over days.

`ipcx` collects that map with minimal overhead, keeps it locally, and turns observations from
many hosts into a reviewable table. It does not generate firewall rules and does not decide
what is allowed.

### Goals

- One static binary, no packages to install on the host, no kernel module or sysctl changes.
- Run for days, survive listener errors, report exactly what was and was not observed.
- Distinguish facts from guesses: every inferred role carries its evidence and confidence.
- Merge results from many hosts without double counting a connection seen from both ends.

### Non-goals (v1)

- Packet capture, payload inspection, protocol parsers (DNS, NTP, RPC).
- Central collection over the network.
- Integration with any firewall or ticket format; output is CSV and JSON only.
- Resume of a previous run, write-ahead log, per-day aggregates, global conflict resolution.
- Deployment tooling (Ansible roles, packages). A systemd unit appears only as a README example.

## Commands

```
ipcx collect [--duration 7d] [--state-dir /var/lib/ipcx] [--checkpoint 2m]
             [--raw] [--go-memory-limit SIZE] [--max-active N] [--max-known N] [--max-unknown N]
ipcx collect --check
ipcx merge FILE... -o merged.json.gz
ipcx report FILE [--format csv|json] [--role known|unknown|all]
             [--min-confidence low|medium|high] [--include-hidden]
ipcx --version
```

- `collect` runs on the observed host as root (or with the capabilities its preflight proves
  sufficient). It writes `<hostname>-<run_id>.json.gz` into the state directory.
- `merge` and `report` run anywhere without privileges.

## Architecture

```
cmd/ipcx                  CLI
internal/conntrack        event listener + dump client over ti-mo/conntrack
internal/sockdiag         socket snapshots over vishvananda/netlink, inode -> process index from /proc
internal/flows            serialized state machine: active flows, classification, aggregate
internal/checkpoint       schema, atomic write, lock file
internal/merge
internal/report
```

Sources (conntrack events, conntrack dumps, socket snapshots, process index) feed one
serialized state machine. Only the state machine mutates state. Checkpoint encoding works on
a short consistent copy and never blocks the event reader. At most one snapshot job runs at a
time.

### Dependencies

- `github.com/ti-mo/conntrack`: pure Go ctnetlink, events and dumps. Versions pinned.
- `github.com/vishvananda/netlink`: `SocketDiagTCP`/`SocketDiagUDP` per address family.
- Standard library for everything else. Build with `CGO_ENABLED=0`.

Known properties of `ti-mo/conntrack` the wrapper must respect:

- Any receive or decode error ends the listener worker; the error arrives on the error channel.
  The listener does not continue by itself.
- Event and error sends are blocking and the error channel is unbuffered. `Close` waits for the
  workers. Both channels must be drained while `Close` runs, or shutdown deadlocks.
- The library does not close the event and error channels. Completion is detected by `Close`
  returning and by the wrapper's own reader tasks finishing.
- A connection joined to a multicast group cannot issue queries: events and dumps use separate
  connections.
- One decoder worker in v1, to keep event order simple.
- `Conn.Dump` (v0.6.0) does not report `NLM_F_DUMP_INTR`; the flag is defined in
  `mdlayher/netlink` but never checked. `ipcx` issues the dump request itself through
  `ti-mo/netfilter` `Conn.Query`, checks the flag on every reply message, and decodes each
  message with the exported `conntrack.Event.Unmarshal`.
- `vishvananda/netlink` socket dumps return partial results together with
  `ErrDumpInterrupted`; `ipcx` treats such a snapshot as incomplete.

## Collection

### Sources

1. **Conntrack events**: NEW, UPDATE, DESTROY on a dedicated connection with an enlarged
   receive buffer. `NoENOBUFS` is never set: losing events must be visible.
2. **Conntrack dumps**: a baseline dump right after the listener is confirmed running, then a
   periodic dump (default every 5 minutes). Periodic dumps are required even without errors:
   with `nf_conntrack_events=2` (auto), flows created before a listener existed may never
   produce events.
3. **Socket snapshots** via sock_diag (TCP all states, UDP), periodic (default 60 s).
4. **Process index**: `socket inode -> pid, comm, start time` from `/proc/<pid>/fd`, periodic,
   with a bounded lifetime. sock_diag itself does not report processes.

Only the current network namespace is observed in v1; this is recorded in coverage.

### Active flow table and lifetimes

An active flow is identified by scope, family, protocol, full original and reply tuples, and a
lifetime. A conntrack ID alone is not a durable identity.

- NEW, baseline dump entry, UPDATE and DESTROY of one lifetime are observations of one flow,
  not several flows.
- A flow removed by DESTROY gets a tombstone. A dump result that started before the DESTROY
  and arrives after it does not resurrect the flow. Tombstones expire after twice the dump
  interval, are swept on events as well as dumps, and are capped at `--max-active`.
- A new flow with the same tuple after a DESTROY is a new lifetime.
- Dump results carry an attempt ID and the listener epoch. Results from an older epoch or an
  older attempt cannot overwrite newer state.
- A dump interrupted by `NLM_F_DUMP_INTR`, failed, or otherwise partial is retried up to three
  times. A partial dump is never used as proof that a flow is gone. Positive observations from
  it may be kept with their provenance.
- Absence from a successful full dump means "no longer in the table", not an exact close time.

### Classification

Each active flow collects evidence; the role follows from the evidence, not from the first
matching rule.

| Evidence | Conclusion | Confidence |
|---|---|---|
| TCP: live NEW event with conntrack state `SYN_SENT` | original source is initiator, original destination is service | high (direction of the attempt, not success) |
| TCP: flow seen only in a dump or UPDATE, start not observed | original destination is the probable service | medium |
| plus a matching LISTEN socket on the service side | confirms the probable service | high |
| a matching LISTEN socket on the original source side | contradicts | `conflict`, full tuples kept |
| UDP: outbound flow whose local source port is inside the local `ip_local_port_range` | weak hypothesis that the destination is the service | low (`port_range`) |
| UDP: first packet from a remote address to a local port that is bound by an unconnected socket and is outside the local `ip_local_port_range` | the local port is the service | low (`udp_bound`) |
| nothing of the above | none | `unknown` |

Rules:

- A LISTEN socket matches only by address, port, family and namespace, with wildcard and
  IPv4-mapped IPv6 semantics, and only if the snapshot is fresh. Port number alone never
  matches. An IPv4 endpoint covered only by an IPv6 wildcard listener is an assumed match,
  because `IPV6_V6ONLY` is not visible in the snapshot: it adds `listen` evidence but never
  raises confidence and never contradicts.
- A NEW event for a flow already seen with the same non-zero conntrack ID is the same
  lifetime. A flow removed because a complete dump no longer lists it gets a tombstone, so a
  late DESTROY does not create a second lifetime.
- Process attribution uses socket and process snapshots no older than twice the snapshot
  interval relative to the flow's last observation; connected UDP sockets must match the peer.
- A UDP socket bound without a peer is **not** evidence of a server: a client using `sendto`
  without `connect` has the same shape. Such sockets are used only for process attribution.
- `ip_local_port_range` describes the local namespace only. It is never applied to a remote
  port.
- Conntrack TCP states and socket TCP states are different enums (`TCP_CONNTRACK_SYN_SENT` is 1,
  socket `TCP_SYN_SENT` is 2). They have separate Go types.
- Simultaneous open is reported as `conflict`.
- "high" is confidence in the inferred role, not a promise that a firewall rule derived from
  it is correct. The README states this.
- ICMP is keyed by type and code; there are no ports.

### Scope and locality

- A flow is `local` to the observer if an endpoint is one of the host addresses in either the
  original or the reply tuple.
- `forwarded` only if no endpoint is local in either tuple. Anything that cannot be decided
  (NAT, VIP, non-local bind) is `unresolved` and keeps full example tuples.
- Loopback and link-local addresses get `scope = observer:<machine_id>`, so that
  `127.0.0.1 -> 127.0.0.1:5432` on two hosts stays two dependencies. All other addresses get
  `scope = global`.
- Address text representation is normalized (IPv4-mapped IPv6 to IPv4, lowercase IPv6).

### Aggregate

Known role key: `scope, family, proto, initiator, service, service_port` (ICMP: `type/code`
instead of the port). The initiator's ephemeral port is dropped from the key only after the
role is established.

Unknown and conflict key: `scope, family, proto, endpoint_a, port_a, endpoint_b, port_b` with
`a` the original source and `b` the original destination, so lifetimes whose first packets went
in opposite directions stay separate records with their own direction. A local port inside the
local `ip_local_port_range` is recorded as `0` (ephemeral); otherwise every client query would
be a record of its own and fill the budget within hours. Low confidence known dependencies use
the known key; their source ports survive in `examples`. Unknown and conflict records have their
own budget.

When better evidence would move a flow to a key whose budget is full, the flow stays on its
previous record, so nothing already observed disappears from the next checkpoint.

Reclassification: while a flow is active it stays linked to its aggregate record. When better
evidence moves it from unknown to known, its accounting moves with it; nothing is counted
twice. Records whose source ports were already dropped are not reclassified retroactively.

Fields per dependency:

| Field | Meaning |
|---|---|
| `role_status` | `known`, `unknown`, `conflict` |
| `direction` | relative to the observer: `inbound`, `outbound`, `local`, `forwarded`, `unresolved` |
| `first_seen`, `last_seen` | time of observation, not connection creation time |
| `sources` | set of `baseline`, `event`, `dump`, `sockdiag` |
| `new_events`, `destroy_events` | event counts |
| `flows_observed` | distinct lifetimes; marked `estimated` after any restart or gap |
| `ever_reply_seen`, `ever_assured` | true if any observed lifetime had it |
| `tcp_states` | set of conntrack TCP states observed |
| `processes` | up to 5 `{comm, endpoint, count}` attributed to the local endpoint; `processes_truncated`; `unknown` when not attributable |
| `examples` | up to 3 full original and reply tuples with timestamps |
| `evidence`, `confidence` | see Classification |

### Limits

- Hard caps on active flows, known records and unknown records (separate budgets), on queues
  and on concurrent snapshot or dump jobs.
- At a cap: existing records keep updating; new records are not stored; `truncated` (or
  `unknown_truncated`) is set with the time it started and `dropped_observations` counts what
  was not stored. This counts observations, not lost unique dependencies.
- Active flows are never silently evicted.
- `--go-memory-limit` calls `debug.SetMemoryLimit`. It is a soft GC target, not a cap on RSS;
  the README says so. No default value.

## Checkpoint format

`<hostname>-<run_id>.json.gz`, `schema_version: 1`.

```
tool:      { version, commit }
host:      { hostname, machine_id, boot_id, kernel, addresses: [{ addr, first_seen, last_seen }] }
run:       { run_id, started_at, generation, checkpoint_at, last_successful_checkpoint, params }
coverage:  {
  netns: "current",
  events_sysctl: 0|1|2,
  intervals: [{ from, to }],
  gaps: [{ kind: map|attribution, from, to, reason }],
  history_incomplete: bool,
  counters: { dump_errors, dump_interrupted, listener_restarts, proc_transient_misses, proc_errors, ... }
}
limits:    { max_active, max_known, max_unknown, truncated, unknown_truncated, dropped_observations }
dependencies: [ ... ]
```

- Every start creates a new `run_id`. A previous result is never extended silently.
- The active flow table is not persisted in v1.
- `gaps.reason` is an open set (`enobufs`, `listener_error`, `decode_error`, `dump_failed`,
  `permission`, `limit`, `shutdown`, ...).
- A gap stays in coverage forever. A successful resync restores current state, not the history
  of the gap: a flow that opened and closed inside the gap is lost.
- `attribution` gaps (no `/proc`, no sock_diag) do not make the map incomplete. A process that
  vanished between `readlink` and reading `comm` (ENOENT) is a transient miss counter, not a
  gap.

### Writing

Temporary file in the same directory, finish gzip, check write and close errors, `fsync` the
file, `rename`. Directory fsync is out of scope for v1; the README states the crash window:
events after the last checkpoint are lost on a crash.

On write failure the previous file stays, the error and the age of unsaved data are logged and
recorded, and the next tick retries. Failed jobs do not queue up.

One collector per state directory, enforced by a lock file. A second instance exits with a
distinct code.

### Raw journal (`--raw`)

Optional rotated journal of netlink events, dump markers and socket snapshots (no packets, no
payload) with timestamps, run, epoch, source type and gap markers. Bounded by size; the
retained time span is reported. Raw journal errors mark the raw journal incomplete, not the
aggregate.

## Error handling

### Preflight (`collect --check`, and at the start of every `collect`)

Checks real operations, per component, and prints each result:

- conntrack dump succeeds;
- event subscription succeeds;
- `nf_conntrack_events` value. `0` is an error unless the user passes an explicit flag
  accepting dump-only observation, which is then recorded in coverage;
- sock_diag dump succeeds;
- `/proc/<pid>/fd` is readable.

Conntrack failure stops the collector. sock_diag or `/proc` failure continues without process
attribution, with a warning and an `attribution` gap. The tool never loads modules, changes
sysctls or generates traffic.

### Listener errors

Any listener error opens a `map` gap with its reason, closes the subscription safely (see
Shutdown), resubscribes and requests a full resync dump. The dump runs like any other dump, so
events keep being read meanwhile; the gap closes when a complete dump of the current epoch
arrives. A job (dump, socket snapshot, process index, checkpoint write) running for more than
three intervals is reported as stuck and opens a gap of the matching kind. Retries are bounded with a
cancellable backoff. When retries are exhausted, `collect` writes a final partial checkpoint and
exits non-zero. There is no long-running dump-only fallback mode in v1.

### Shutdown

Triggered by SIGTERM, SIGINT or `--duration`. Uses a separate bounded shutdown context.

1. Stop new subscriptions, timers and backoffs.
2. Call `Close` on the listener while still draining both its event and error channels.
3. Wait for library workers and own readers to finish.
4. Process the already accepted queue.
5. Record the coverage boundary: events still in the kernel socket buffer at close are not
   observed.
6. Write the final checkpoint.
7. Release the lock.

If in-flight jobs do not finish within the shutdown timeout, they are recorded as stuck gaps
and the final checkpoint is still written, with exit code 1. `os.Exit` is never called before
this sequence finishes. A failed final write exits non-zero
even if an older checkpoint exists. A run that never produced a checkpoint is a failed run.

### Exit codes

`0` success; `1` runtime failure (listener retries exhausted, final write failed); `2` usage
error; `3` preflight failed; `4` state directory locked.

### Logging

`log/slog` JSON to stderr.

## Merge

- Input: checkpoint files from any number of hosts and runs.
- Per `run_id`, the highest `generation` wins, after checking that host, boot and schema agree.
  Same `run_id` and `generation` with different content is an input error.
- Dependencies are joined by key. Observations stay per observer and run: direction, counters
  and coverage are never summed across observers, because both ends may see the same
  connection.
- A conflict is reported when observers disagree on the role for the same transport evidence.
  Other disagreements are kept as separate inferences with provenance. No global resolver.
- Coverage of every input run is carried into the output.

## Report

### CSV

One row per dependency and observer run.

```
role_status, scope, proto, initiator, service, service_port, icmp_type, icmp_code,
endpoint_a, port_a, endpoint_b, port_b, observer, run_id, direction, confidence, evidence,
processes, first_seen, last_seen, flows_observed, flows_estimated, ever_reply_seen,
coverage_status
```

- For `unknown` and `conflict` rows, `initiator`, `service` and `service_port` are empty;
  `endpoint_*` and `port_*` are filled. For known rows the endpoint columns are empty.
- `coverage_status` for the observer run: `incomplete` when the history has a map gap, a map
  gap is still open, events were not enabled (`nf_conntrack_events` not 1 or 2) or the run has
  not finished (last interval open); `truncated` when a limit was hit; `incomplete+truncated`
  for both; otherwise `complete`. Attribution gaps do not change it.
- Loopback, `forwarded` and `unresolved` rows are hidden by default; `--include-hidden` shows
  them.

### JSON

Everything, including coverage, examples and per-observer observations.

### Summary

`report` prints to stderr how many records were hidden and why, and whether any input run is
incomplete or truncated. Exit code stays 0; the summary is informational.

## Testing

### Unit

- Classifier: table tests, including:
  - unconnected UDP `sendto` to port 53 (must not make the client a service);
  - outbound TCP from a source port that equals another socket's LISTEN port;
  - TCP flow open before collection started (baseline only);
  - one flow moving from unknown to known;
  - `A -> B` after merge: outbound at A, inbound at B;
  - two localhost PostgreSQL dependencies on two hosts stay separate.
- Aggregate, reclassification, merge, checkpoint roundtrip and atomic write with injected
  failures.
- JSON is checked by invariants and roundtrip, not golden files. One small CSV golden file
  covers columns and quoting.
- Run with `-race`.

### Pipeline with fake sources

Conntrack, sock_diag and `/proc` sit behind interfaces. Fakes replay scripted sequences:

- shutdown while a worker is blocked on an event send, and on an error send;
- dump result arriving after a DESTROY of the same flow;
- repeated NEW for the same tuple;
- repeated resync without growth of `flows_observed`;
- ENOBUFS in the middle of a stream;
- `NLM_F_DUMP_INTR`;
- persistent checkpoint failure, final checkpoint failure;
- `nf_conntrack_events=0`;
- hitting each limit.

The adapter is also tested against the real library channels so a fake cannot hide a deadlock.
Lifecycle tests use `goleak` and explicit completion timeouts.

### Integration (Linux, root)

Build tag `integration`. The test binary is built unprivileged and run with `sudo`, `-count=1`.

Fixture: two network namespaces joined by veth, documentation addresses for IPv4 and IPv6, no
external network. An nftables base chain with a hook and a `ct state` rule in each namespace
enables tracking. The events sysctl is set inside the test namespaces. The collector and the
traffic helpers run as separate processes via `ip netns exec`.

Sequence with explicit barriers, no sleeps:

1. tracking ready;
2. open a long-lived TCP connection;
3. start collector, wait for listener ready and baseline complete;
4. short TCP connections, UDP request and reply, UDP `sendto` without `connect`;
5. wait for the expected observations;
6. stop the collector normally;
7. assert on the persisted checkpoint: the long-lived flow is present from baseline, new flows
   are present from the event source (not only from dumps), the helper process is attributed.

A missing kernel feature or permission fails the job with a diagnostic; it is never a silent
skip. The job logs `uname -r` and the runner image version.

### CI (GitHub Actions)

- On push and pull request: `go vet`, `staticcheck`, unit and pipeline tests with `-race`, build
  for `linux/amd64` and `linux/arm64`.
- Integration job on `ubuntu-24.04` (pinned, not `ubuntu-latest`).
- On tag `v*`: GoReleaser builds `ipcx_<version>_linux_<arch>.tar.gz` (binary, README, LICENSE)
  and `checksums.txt`. A smoke step unpacks the amd64 archive and runs `--version`, `merge` and
  `report` on a small fixture. arm64 is checked for build, archive and checksum only and is not
  claimed as runtime tested.

### Manual

Linux 5.4 (Ubuntu 20.04) is verified manually before it is listed as tested. Load and overhead
are measured on a pilot, not in CI.

## Documentation

English. `README.md`: what it does, install from release, `collect --check`, running for days,
example systemd unit, report fields, limitations (gaps, events disabled, flows without events,
unknown roles, crash window, soft memory limit, "high" confidence meaning), tested kernels.
`LICENSE`: MIT. Examples use documentation address ranges only.
