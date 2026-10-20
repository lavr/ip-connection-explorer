# AGENTS.md: ipcx

Guidance for anyone changing this repository, human or agent. Read it before the first edit.
User documentation is [README.md](README.md); the design and its reasons are in
[docs/design.md](docs/design.md). When the code and the design disagree, fix one of them in the
same change.

## What this is

`ipcx` runs on a Linux host for days, records which network dependencies the host actually has,
and turns checkpoints from many hosts into one table for a firewall request. It reads conntrack
events and dumps, sock_diag socket snapshots and `/proc/<pid>/fd`. One static Go binary,
`CGO_ENABLED=0`, Go 1.24.

## Hard rules

- **Observe only.** `ipcx` never adds firewall rules, never enables connection tracking, never
  changes sysctls and never captures packets or payload. A feature that needs any of that is a
  design discussion first, not a patch.
- **Kernel module autoload is fine.** Opening netlink can make the kernel load
  `nf_conntrack_netlink`, `inet_diag`, `tcp_diag`, `udp_diag`, exactly as `ss` and `conntrack`
  do. Do not add guards against it and do not unload modules. Check usefulness instead: is there
  anything to observe (`nf_conntrack_count`, events enabled).
- **Bounded memory.** Every table has a limit (`--max-active`, `--max-known`, `--max-unknown`,
  tombstone queue). A new map that grows with traffic needs a limit and a `truncated` path in the
  report.
- **Never lose data silently.** A gap, a dropped event, an interrupted dump or a hit limit is
  recorded in the checkpoint and shows up as `incomplete` or `truncated`. If you cannot record
  it, fail loudly.
- **The event reader must not block.** Heavy work (dumps, snapshots, checkpoint encoding) runs
  outside the state machine goroutine and hands results back. The load test guards this.
- **No real data in the repository.** Tests and fixtures use documentation addresses
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) and invented host
  names. Checkpoints from real hosts never go into git, issues or PR descriptions.

## Layout

```
cmd/ipcx                 CLI: collect, merge, report, flags, exit codes, profiling
internal/model           shared types and enums
internal/conntrack       ctnetlink events and dumps (Linux only), kernel readiness checks
internal/sockdiag        socket snapshots over sock_diag (Linux only)
internal/procindex       inode -> process index from /proc
internal/hostinfo        machine-id, boot_id, kernel, ephemeral port range
internal/flows           the state machine: lifetimes, classification, socket index, aggregate, limits
internal/collector       run loop: sources, resync, stuck jobs, preflight, shutdown order
internal/checkpoint      schema, atomic write with generation fence, lock file
internal/rawlog          optional rotated raw journal (--raw)
internal/merge           merge checkpoints from several runs
internal/report          CSV and JSON output, filters, summary
test/integration         privileged network-namespace test (real kernel, nftables)
testdata                 synthetic checkpoints for merge and report
```

`internal/flows` is pure and deterministic: it gets events, dump results and socket snapshots
as values and never touches the kernel. Put logic there and test it there. The netlink
adapters stay thin and are behind `//go:build linux`; `internal/collector/sources_other.go`
keeps the rest building on macOS.

## Working on it

- **Tests first.** Write the failing test, watch it fail for the right reason, then fix. A bug
  fix comes with the test that reproduces it.
- Commands:

  ```sh
  make test               # unit tests (macOS or Linux)
  make vet lint           # go vet, staticcheck
  make load               # open-loop load test, 10k events/s for 10 s, must keep 99%
  make test-linux         # unit tests in a Linux container, needed for the netlink adapters
  make integration-docker # namespace integration test in a privileged container
  make integration        # the same on a Linux host, with sudo
  make cross              # linux/amd64 and linux/arm64 builds
  ```

  On macOS the Linux-only packages are not compiled by `make test`; run `make test-linux` and
  `make integration-docker` (Docker or OrbStack) before calling a collector change done.
- CI (`.github/workflows/test.yml`) runs vet, race tests, the load test, cross builds and the
  integration test on every push and pull request. Keep it green on `main`.
- Performance changes come with numbers: run with `--cpuprofile`/`--memprofile` before and after,
  and keep or extend the load test so the regression cannot come back.
- Checkpoint schema changes bump `checkpoint.SchemaVersion` and update the fixtures. `merge` and
  `report` reject any other version, and collections run for a week, so either keep a reader for
  the previous version or say in the release notes which release still reads the old files.
- Documentation, code comments and commit messages are in English. Keep comments sparse; explain
  why, not what.

## Commits

- One line, `type: summary` in lower case (`fix:`, `feat:`, `test:`, `docs:`, `perf:`, `ci:`,
  `chore:`), imperative, no trailing period.
- No co-author or tool attribution trailers. No long dashes (U+2014) in commit messages.
- One logical change per commit; tests go in the same commit as the code they cover.

## Releases

- Only through `./release.sh` from `main`: `./release.sh status`, then `./release.sh app patch`
  (or `minor`, `major`, an explicit `X.Y.Z`). `--dry-run` previews; without a terminal pass
  `--yes`. Tags are plain `X.Y.Z`.
- The tag starts `.github/workflows/release.yml`: tests again, a GoReleaser snapshot with a smoke
  test, then the publish. Do not create or push release tags by hand unless the script cannot
  work, and then say why.
- After an interrupted release, check `./release.sh status` and re-run with an explicit version.
- Release notes must not name real hosts, networks or organisations.

## Agent skill

`plugins/ipcx/skills/ipcx/` is the user-facing skill for Claude Code and Codex: how to run a
collection, read the report and prepare a firewall request. It is not developer documentation.
When a flag, a default, a column, an exit code or a preflight message changes, update the skill
and its `references/` in the same change, and bump the plugin version in
`plugins/ipcx/.claude-plugin/plugin.json`, `plugins/ipcx/.codex-plugin/plugin.json` and
`.claude-plugin/marketplace.json` together.
