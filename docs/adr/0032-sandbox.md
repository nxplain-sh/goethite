# ADR 0032: Landlock and seccomp, applied by goethite itself

- **Status:** Accepted
- **Date:** 2026-10-09

## Context

goethite parses untrusted input all day: DNS messages, filter lists, API requests, other cluster
members' Raft messages. Parsers are bounded and fuzzed, and the binary forbids `unsafe` where it
parses, but a bug in goethite or a dependency could still give an attacker code execution in the
process (B1 to B6 in the [threat model](../THREAT_MODEL.md)). Today that process can read
whatever its user can read and call any system call the kernel offers.

The systemd units sandbox goethite from the outside (read-only file system, a system call filter,
IP sockets only). But goethite also runs without them: in containers, started by hand, under other
init systems. And the unit cannot know which files the config file names.

Two constraints shape any sandbox here:

- **Upgrades.** `SIGUSR2` makes goethite start the new binary and hand it its sockets
  ([ADR 0012](0012-zero-downtime-upgrades.md)). Landlock domains and seccomp filters are inherited
  across `execve`, so the new goethite starts inside the old one's sandbox.
- **Threads.** Landlock restricts the calling thread and what it starts later; it cannot restrict
  threads that already run (ABI 8 can, but few kernels have it).

## Decision

**After dropping privileges and before starting any thread, each goethite process confines itself
with Landlock (files, and TCP listening) and a seccomp filter (system calls), on Linux.** The
policy depends on the process:

| | Read | Change | Start programs | Sockets |
| --- | --- | --- | --- | --- |
| `goethite run` | `/usr`, `/lib*`, `/bin`, `/sbin` (also executable), `/proc`, `/etc/ld.so.cache`, `/etc/localtime`, the config file's directory, the directories of the certificates, keys and services file it names, the local lists directory, `/etc/passwd` with `server.user` | the store's directory, `cache_dir`, the runtime directory | yes (upgrades) | IPv4, IPv6, Unix |
| `goethite witness` | nothing | the store's directory | no | IPv4, IPv6, Unix |
| `goethite vrrp` | nothing | nothing | no | also netlink, packet |

All three may connect to systemd's notification socket. None opens a new TCP listener (Landlock
`BIND_TCP`): every listener exists before the sandbox.

**Rules name directories, not files.** A Landlock rule holds the inode it was made for. An upgrade
replaces the binary, a renewal replaces a certificate (often behind a symbolic link), an editor
replaces the config, and each is a new inode. So rules cover the directories holding them, both as
named and with links resolved. Replacing the binary with a new file and sending `SIGUSR2`, and a
`SIGHUP` reload, were checked under systemd with the sandbox on.

**The system call filter is a deny-list.** It returns `EPERM` for calls goethite never makes:
mounting, modules, rebooting, swapping, `ptrace` and `process_vm_*`, `perf_event_open`, BPF,
`userfaultfd`, `io_uring_*`, `unshare` and `setns`, keyrings, setting the clock or the host name,
file handles, and old x86 I/O; and for `socket` with a family other than those allowed. An
allow-list would be tighter, but the new goethite of an upgrade must start inside the old one's
filter: a newer libc or tokio making a call the old list lacked would break upgrades. The filter
is built for x86-64 and 64-bit Arm from a table of numbers in the code, not from `libc`, to keep
the dependency list as it is.

**Best effort, and said.** With an older kernel, Landlock enforces what it supports (the crate
handles each ABI's rights); without Landlock, only seccomp applies. A sandbox around goethite that
refuses the calls (`EPERM`, `EACCES`, `ENOSYS`) counts as not having them: systemd before 253
leaves `seccomp` and the Landlock calls out of `@system-service`, which the units therefore allow
explicitly, and container runtimes may refuse them too. goethite then runs within that outer
sandbox. The log names the kernel's Landlock ABI and the number of denied calls, or warns. Any
other failure, such as a filter the kernel finds invalid, stops goethite with a message naming
`[security] sandbox = false`, which turns it off.

**Local lists come from one directory.** `[filter] local_lists_dir` (default `lists` beside the
config file, `/etc/goethite/lists` for the packages) is the only place lists given by a `path` are
read from, checked lexically (absolute, no `..`, inside the directory as configured or resolved)
before Landlock enforces it at open. Without that, the read rules would have to cover any path an
API client names. A list elsewhere is skipped and its status says why: filtering fails open,
goethite starts. This is a breaking change.

**Dependencies:** `landlock` 0.4.7 and `seccompiler` 0.5.0, both Linux only, both safe APIs
(their `unsafe` is the system calls), both MIT OR Apache-2.0 and maintained by the Landlock
author and the Firecracker team respectively.

## Alternatives considered

- **Rely on systemd and container runtimes.** They do it well, but only where they are used, and
  they cannot narrow file access to the files the config names. The units keep their own sandbox;
  the two stack.
- **A seccomp allow-list.** Stronger against unknown calls, but every libc, tokio or kernel change
  risks breaking startup or, worse, upgrades in place. Revisit if upgrades stop inheriting the
  filter (for example by re-executing through systemd).
- **File rules on exact files.** Tighter, but renewals and upgrades replace files, and Landlock
  rules follow inodes: reloads and upgrades would fail.
- **Landlock rules for outgoing TCP.** Upstreams, list hosts and cluster members can be on any
  port, some added at run time; the policy would have to follow the configuration. Left in the
  backlog.
- **`libseccomp` bindings.** A C library; seccompiler is pure Rust and enough for a deny-list.

## Consequences

- A bug turned into code execution can read little beyond goethite's own files and change only
  its state; it cannot mount, trace, load modules, use BPF or io_uring, or (in the witness and
  vrrp) start programs.
- Lists given by a path must move into `local_lists_dir` (breaking, documented in the changelog).
- An upgrade runs inside the old sandbox: if the config file moved the store, certificates or
  lists to new directories, restart instead of upgrading in place. A future version that needs
  new paths at startup needs a restart for that one upgrade.
- `/proc` stays readable for `goethite run`, since the new goethite of an upgrade counts its
  threads there; so do the system directories, since it must start from them.
- `clone3` cannot be filtered by flag, so namespaces created through it are not refused (backlog).
