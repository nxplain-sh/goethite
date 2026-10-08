# ADR 0012: Upgrades and restarts without dropping queries

- **Status:** Accepted
- **Date:** 2026-10-08

## Context

Phase 3 asks for graceful reload via socket handoff. A DNS server that restarts refuses queries
for as long as it is down, and clients notice. For goethite that is about a second, mostly
building the filter. Plain restarts are needed for:

- new binaries;
- config file changes;
- recovery after a crash.

Two constraints shape the design:

- **Privileges.** goethite drops every capability after binding port 53. A new process started
  by it cannot bind port 53 again.
- **The store.** redb allows one process per database file. The old and new process cannot both
  have it open.

## Decision

**Upgrade by handing over the sockets.** On `SIGUSR2` the running process (the parent):

1. starts the binary at the path it was itself started from. The path is remembered at startup,
   because package managers replace the file and `/proc/self/exe` then points at the deleted
   one;
2. passes the new process (the child) every listening socket over a private Unix socket. The
   socket is `SOCK_SEQPACKET`, the descriptors go as `SCM_RIGHTS`, and they are sent in chunks of
   200 to stay below the kernel's limit;
3. once the child has adopted the sockets, stops its own control plane: the API, the cluster,
   list downloads and the query log, which closes the store;
4. the child opens the store, builds its filter and starts answering on the same sockets, then
   tells systemd it is the main process now (`MAINPID=`, `READY=1`);
5. the parent stops reading the sockets, finishes the queries in flight and exits.

Until step 5 the parent answers every query. For a moment both processes read the same sockets,
and the kernel gives each datagram and connection to one of them. Nothing is dropped:

- the kernel queue belongs to the socket, not the process;
- the API's pending connections wait in its listen backlog;
- the only gap is a few seconds without a query log, while the store changes hands.

**Failure keeps the old process.** If the child fails before step 3, the parent kills it and
carries on untouched. If it fails later, the parent starts its control plane again. The child
reports its errors over the socket, every step has a timeout, and the parent keeps answering
throughout.

**Authentication** is the kernel's:

- the socket is created mode 0600, in the service's private runtime directory (`/run/goethite`,
  0700), and removed once the child connects;
- the parent checks with `SO_PEERCRED` that the connecting process is the one it started;
- the child, already unprivileged, receives the keys (the API's TLS key, the cluster's) as well,
  since it cannot read root-only files. It prefers the files when it can read them, which picks
  up renewed certificates.

**systemd keeps the sockets too.** After startup goethite stores its sockets in systemd's
file-descriptor store (`FDSTORE=1`, named like `dns-udp-0-3` and `api-0`). When systemd restarts
the service, whether after a crash or with `systemctl restart`, it passes them back
(`LISTEN_FDS`). Queries sent meanwhile wait in the kernel and are answered once goethite is
back, instead of being refused. Sockets taken back are checked against the config file: each
must be a socket of the right kind, bound to the right address. If the listen addresses
changed, goethite tells systemd to drop the stored ones and binds afresh.

**One `unsafe` block.** Taking descriptors by number (`OwnedFd::from_raw_fd`) cannot be done
safely. It is done once, in the binary:

- first thing in `run`, before any file is opened, so nothing can have reused the numbers;
- only when `LISTEN_PID` names this process;
- each number taken exactly once, and each socket checked before use.

The workspace lint is `deny`. Every library crate carries `#![forbid(unsafe_code)]`, and the
binary allows `unsafe` in that one function. The handoff itself uses only safe rustix calls.

**The unit** becomes `Type=notify` with `NotifyAccess=all`, so the new process can name itself
the main one. It also gets `RuntimeDirectory=goethite`, `FileDescriptorStoreMax=2048` and
`AF_UNIX`. One subtlety cost an outage in testing: the old process must not send `STOPPING=1` on
its way out. systemd accepts it from any process of the service and would then stop the new
one.

## Consequences

- `systemctl kill --signal=SIGUSR2 --kill-whom=main goethite` upgrades without dropping a query:
  1,276 queries during a test upgrade under systemd, none lost. It also applies config changes,
  except new listen addresses. A crash or restart queues queries instead of refusing them.
- The control plane must be able to stop completely and start again. That shaped how the binary
  is put together: background tasks run in a set the control plane owns, the query log can
  close, and the DNS server's query log handle can be swapped.
- Upgrades by handoff are Linux only, like production.
- `systemd-analyze security` goes from 1.5 to 1.7 (Unix sockets).

## Alternatives considered

- **Re-executing in place (`execve` on the same PID).** systemd needs no new main PID, but the
  process stops answering while the new image starts and builds its filter. Queries queue in the
  socket buffers, which overflow under load.
- **`SO_REUSEPORT` with fresh sockets.** It needs the privilege to bind port 53 again, and
  datagrams queued on the old sockets are lost when they close.
- **A crate for `LISTEN_FDS` (listenfd).** The same unsafe call, inside a dependency.
  Considered, and declined in favor of one audited block.
- **Socket activation (`.socket` units).** systemd would own the sockets from the start. It
  splits configuration between the unit and the config file, and does not help with upgrades.
