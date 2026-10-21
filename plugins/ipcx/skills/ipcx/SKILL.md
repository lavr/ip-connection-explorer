---
name: ipcx
description: Use when a Linux host is about to move to another network segment, VLAN or behind a new firewall and someone needs to know which network access rules to request, or when asked to install or run ipcx (ip-connection-explorer), check a host with `ipcx collect --check`, merge ipcx checkpoints, or read an ipcx report and turn it into a firewall request.
---

# Mapping a host's network dependencies with ipcx

`ipcx` runs on a Linux host for days and records who it talks to: inbound clients, outbound
services, the local process on each side. Checkpoints from many hosts are merged into one table
that becomes the list of firewall rules to request. It only observes: no packet capture, no
payload, no rules, no kernel settings.

Three commands:

- `ipcx collect` on each observed host, as root, Linux only;
- `ipcx merge` and `ipcx report` anywhere, macOS included, on copied checkpoint files.

Flags, columns and evidence values: [references/report.md](references/report.md).
Install and run recipes: [references/running.md](references/running.md).

## Ask before touching a host

`collect` needs root and runs for days on hosts that are often production. Before running it,
or `--check`, on any host, confirm with the user which hosts, for how long, and where the state
directory goes. Reading a checkpoint file the user already has needs no confirmation.

Never enable connection tracking, add `ct state` rules, load conntrack with `enable_hooks=1` or
change sysctls to make `ipcx` work, even when that is the obvious fix. Those change packet
handling on the host. Explain the option and its cost (below) and let the owner decide.

## Workflow

1. **Preflight.** `sudo ipcx collect --check --state-dir DIR`. Every line is `ok`, `warn` or
   `fail`; exit code `3` means a `fail`. Interpret before going on:

   | Line | Meaning and next step |
   |---|---|
   | `fail conntrack_kernel` "not active on this host" | No conntrack at all. Nothing to observe; see *Hosts without conntrack*. |
   | `warn conntrack_kernel` "has no entries" | The module is loaded but nothing uses it, so traffic is not tracked. On a busy host the map will stay empty. Same section. |
   | `fail events_sysctl` `nf_conntrack_events=0` | The kernel sends no events. `--allow-no-events` collects from periodic dumps only and misses short connections; tell the user. |
   | `fail conntrack_dump` / `conntrack_events` | Not root, or netlink blocked (container, seccomp). Run as root on the host itself. |
   | `fail state_dir` | Directory not writable; pick another. |
   | `warn sock_diag` / `warn proc_fd` | Collection works, but roles and process names will be weaker. |

2. **Collect.** At least a week; weekly jobs and backups are what a short window misses:
   `sudo ipcx collect --duration 7d --state-dir /var/lib/ipcx`. Run it as a transient or regular
   systemd unit so it survives the SSH session (recipe in references/running.md). Exit code `4`
   means another collector holds that state directory.

   For a first look on a new kind of host, run 10 to 30 minutes first and watch CPU and RSS. On a
   busy load balancer expect around 10% of one core and 150 to 300 MiB. Do not set a CPU quota:
   a starved event reader loses events and the report marks the run `incomplete`.

3. **Gather.** The final checkpoint is `<hostname>-<run_id>.json.gz` in the state directory; a
   periodic one is rewritten every `--checkpoint` (2m) while it runs, so a crash loses at most
   that much. Copy the files to one place.

4. **Merge and report.**

   ```sh
   ipcx merge host-a-*.json.gz host-b-*.json.gz -o all.json.gz
   ipcx report all.json.gz --format csv > dependencies.csv
   ```

   `report` prints a summary to stderr: rows, hidden rows, incomplete and truncated runs,
   conflicts. Read it and pass it on; it is the honest part of the result.

5. **Turn it into a firewall request.** See the next section.

## From report to firewall request

- Start from `--role known`. Each row is `initiator -> service:service_port/proto`. Both ends
  report the same dependency (outbound on the client, inbound on the server), so deduplicate on
  `(proto, initiator, service, service_port)` and keep the observers as evidence.
- Only traffic that will cross the new firewall needs a rule. Drop pairs that stay inside one
  segment after the move; the user knows the target layout, ask for it.
- `confidence` is about the role, not the rule. `high` with `listen` evidence is solid.
  `conntrack_original` without `listen` means the direction was assumed; check the port against
  what runs on the host.
- `unknown` and `conflict` rows (`--role unknown`) need a human: UDP without a known server side,
  or a port that both sides listen on. Present them separately, with both ports and processes,
  instead of guessing a rule.
- Ephemeral ports are not services. A row shows `0` for a local ephemeral port nothing listens on.
- Group the request by service (`service:port/proto` with the list of initiators), and name the
  process from `processes` so the security team can see why the rule exists.
- State the coverage: collection window per host, and every run the summary calls `incomplete`
  or `truncated`. Absence of traffic in the window is not proof that a dependency does not exist.

Hidden by default (`--include-hidden` shows them): loopback and link-local, `forwarded` (no
local endpoint, including broadcasts from neighbours and traffic routed through the host, such
as Kubernetes pod traffic on a node), and `unresolved` (NAT other than plain source NAT). They
never need a host firewall rule but can explain surprises. Pod or container traffic masqueraded
behind the host address is not hidden: it is `outbound` from the host address with
`conntrack_snat` evidence, which is the source a network firewall sees.

## Hosts without conntrack

`ipcx` sees only what conntrack tracks. Since kernel 4.x conntrack tracks nothing until a rule
needs it, so hosts without stateful firewall rules (often load balancers and web servers) give
`fail` or an empty `warn`. Options to present to the owner, not to apply:

- Turn tracking on for the collection window: `modprobe nf_conntrack enable_hooks=1` and a
  raised `net.netfilter.nf_conntrack_max`, removed afterwards. Cost: per-packet CPU, memory for
  the table, and dropped packets if the table fills. Estimate the table first: open connections
  plus new connections per second times 120 s (the TIME_WAIT timeout), and compare with
  `nf_conntrack_max`.
- Collect elsewhere: the peers that do track connections see this host's traffic from their side.
- Use other sources for that host: proxy access logs, `ss` snapshots.

## Permanent matrix in Prometheus (beta)

When the user wants the matrix all the time rather than for one window, `collect
--prometheus-exporter.listen ADDR` serves it for Prometheus. Without `--duration` it runs until
stopped and writes no checkpoint. The port has no TLS or authentication: ask which address to
bind and who may scrape it before starting it. Flags, metrics and caveats:
`references/running.md`.

## Privacy

Checkpoints and reports contain host names, machine IDs, addresses and process names. Keep them
where the user's infrastructure data is kept. Do not paste them into public issues, gists or
chats; replace the addresses first if an example is needed.
