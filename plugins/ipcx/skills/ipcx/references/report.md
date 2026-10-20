# ipcx flags, report columns and evidence

## Commands

| Command | Flags (defaults) |
|---|---|
| `ipcx collect` | `--duration 7d`, `--state-dir /var/lib/ipcx`, `--checkpoint 2m`, `--dump-every 5m`, `--snapshot-every 60s`, `--raw`, `--go-memory-limit SIZE`, `--max-active 200000`, `--max-known 100000`, `--max-unknown 50000`, `--allow-no-events`, `--check`, `--cpuprofile FILE`, `--memprofile FILE` |
| `ipcx merge FILE... -o OUT` | |
| `ipcx report FILE` | `--format csv\|json` (csv), `--role known\|unknown\|all` (all), `--min-confidence low\|medium\|high` (low), `--include-hidden` (off) |

Durations accept Go units plus `d` for days (`36h`, `7d`).

Exit codes: `0` success, `1` runtime failure, `2` usage error, `3` preflight failed, `4` state
directory locked by another collector.

## Report columns

One row per dependency and observer run.

| Column | Meaning |
|---|---|
| `role_status` | `known`, `unknown` or `conflict` |
| `scope` | `global`, or `observer:<machine-id>` for loopback and link-local addresses |
| `proto` | `tcp`, `udp`, `icmp`, `icmpv6` |
| `initiator`, `service`, `service_port` | filled for known roles |
| `icmp_type`, `icmp_code` | ICMP instead of a port |
| `endpoint_a`, `port_a`, `endpoint_b`, `port_b` | both ports in the original direction, for unknown and conflict rows; `0` is a local ephemeral port nothing listens on |
| `observer`, `run_id` | which host and run saw it |
| `direction` | relative to the observer: `outbound`, `inbound`, `local`, `forwarded`, `unresolved` |
| `confidence`, `evidence` | how the role was decided |
| `processes` | local processes, `comm@address[:port]` |
| `first_seen`, `last_seen` | when the collector observed it, not when the connection started |
| `flows_observed` | connection lifetimes seen |
| `flows_estimated` | `true` when the count is an estimate because of gaps or restarts |
| `ever_reply_seen` | a reply was seen at least once; `false` on TCP often means a failed or filtered connection attempt |
| `coverage_status` | `complete`; `incomplete` (a gap, events disabled, or the run had not finished); `truncated` (a limit was hit); `incomplete+truncated` |

## Evidence

| Evidence | Meaning |
|---|---|
| `conntrack_new` | a live NEW event in TCP state `SYN_SENT`: the initiator is certain |
| `conntrack_original` | the connection was already open, or its start was not seen; the original direction is assumed |
| `listen` | a listening socket on the service side confirms it |
| `listen_contradicts` | the supposed client listens on that port: role is `conflict` |
| `port_range` | UDP from a local ephemeral port: weak hint |
| `udp_bound` | UDP from outside to a bound, non-ephemeral local port: weak hint of a server |
| `none` | nothing decides the role: `unknown` |

## Limitations to state in any result

- Only flows conntrack tracks are seen; hosts without stateful rules may track nothing.
- Only the host's own network namespace; containers in their own namespaces are not observed
  directly (on a Kubernetes node their routed traffic shows up as `forwarded`).
- A gap in the event stream is permanent: a connection that opened and closed inside it is lost.
- UDP roles are often unknown.
- Absence of traffic in the window is not proof that a dependency does not exist.
