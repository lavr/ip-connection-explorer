# Installing and running ipcx

## Install

Releases: https://github.com/lavr/ip-connection-explorer/releases, archives for `linux_amd64`
and `linux_arm64` plus `checksums.txt`. The binary is static.

```sh
V=0.1.1   # take the latest release
curl -fsSLO https://github.com/lavr/ip-connection-explorer/releases/download/$V/ipcx_${V}_linux_amd64.tar.gz
curl -fsSLO https://github.com/lavr/ip-connection-explorer/releases/download/$V/checksums.txt
sha256sum --check --ignore-missing checksums.txt
tar -xzf ipcx_${V}_linux_amd64.tar.gz
sudo install -m 0755 ipcx /usr/local/bin/ipcx
ipcx --version
```

Hosts without internet access: download on a workstation, check the checksum there, copy the
binary with `scp` (through the jump host the user names).

## Short trial run

A transient unit with a memory ceiling, stopped after the duration:

```sh
sudo systemd-run --unit ipcx-trial --collect --property=Nice=10 --property=MemoryMax=512M \
  /usr/local/bin/ipcx collect --duration 15m --state-dir /var/tmp/ipcx-trial
```

Watch it once a minute:

```sh
P=$(systemctl show -p MainPID --value ipcx-trial)
grep VmRSS /proc/$P/status
top -b -n 1 -p $P | tail -1
cat /proc/sys/net/netfilter/nf_conntrack_count
journalctl -u ipcx-trial -o cat | grep -E '"level":"(WARN|ERROR)"'
ls -la /var/tmp/ipcx-trial   # the periodic checkpoint appears after --checkpoint (2m)
```

Stop early with `sudo systemctl stop ipcx-trial`: SIGTERM writes the final checkpoint, and the
journal logs each shutdown stage up to `final checkpoint written`.

## Week-long run

```ini
# /etc/systemd/system/ipcx.service
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

```sh
sudo systemctl daemon-reload
sudo systemctl start ipcx
```

`Restart=no` is deliberate: a restarted run starts a new `run_id`; the gap between runs is
recorded and `merge` combines the runs. Start it again by hand if it stopped early, after reading
why in `journalctl -u ipcx`.

## Many hosts

Use the user's configuration management (Ansible, Salt) to copy the binary, start the unit and
fetch `/var/lib/ipcx/*.json.gz` afterwards. Do not run it across a fleet without the user's
explicit list of hosts and window.

## Prometheus exporter (beta)

```sh
sudo systemd-run --unit ipcx-exporter --property=Nice=10 --property=MemoryMax=512M \
  /usr/local/bin/ipcx collect --state-dir /var/lib/ipcx-exporter \
  --prometheus-exporter.listen 10.0.0.5:9917
curl -s http://10.0.0.5:9917/metrics | grep -E '^ipcx_(exporter_ready|exporter_series|gaps_total)'
```

- Without `--duration`: runs until stopped, no checkpoint, `--raw` refused. With `--duration`
  the checkpoint is written as usual and the exporter runs beside it.
- Use a separate state directory if a checkpoint run may happen on the same host: one state
  directory admits one collector (exit code `4`).
- A port already in use fails at start with exit code `3`.
- `ipcx_connections_finished_total` grows when a connection ends; long-lived pools show only in
  `ipcx_connections_active`. Query both to answer "who talks to whom".
- `ipcx_exporter_ready 0` means the first conntrack dump has not been applied yet.
- `ipcx_exporter_series_rejected_total` growing means the table is full: raise
  `--prometheus-exporter.max-series` or lower `--prometheus-exporter.ttl`.

## Logs

`collect` logs JSON lines to stderr (the journal under systemd). Messages worth a look:
`conntrack listener failed` (the event stream broke; it is resubscribed and resynchronised, and
the gap is recorded), `conntrack dump failed`, `job is stuck` (a dump or snapshot did not
finish), `checkpoint write failed`, `conntrack listener retries exhausted` (collection ends),
and the `shutdown` stages. Gaps, dropped events and hit limits are counted in the checkpoint and
summarised by `ipcx report`.

## Debugging a slow or heavy run

`--cpuprofile FILE` and `--memprofile FILE` write Go profiles (mode 0600, never overwriting an
existing file). `--go-memory-limit 512MiB` asks the garbage collector to try harder; it is not a
cap. Hard bounds are `--max-active`, `--max-known`, `--max-unknown`.
