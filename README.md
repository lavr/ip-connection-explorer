# ipcx

`ipcx` (ip-connection-explorer) observes the network dependencies a Linux host actually has,
using conntrack and sock_diag, so that firewall rules can be requested before the host moves
to another network segment.

Work in progress. See [docs/design.md](docs/design.md).
