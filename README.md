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
| `ipcx collect` | `--duration 7d`, `--state-dir /var/lib/ipcx`, `--checkpoint 2m`, `--dump-every 5m`, `--snapshot-every 60s`, `--raw`, `--go-memory-limit SIZE`, `--max-active 200000`, `--max-known 100000`, `--max-unknown 50000`, `--allow-no-events`, `--check` |
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

Loopback and link-local, forwarded and unresolved (NAT) rows are hidden unless
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
