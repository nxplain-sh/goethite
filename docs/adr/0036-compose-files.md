# ADR 0036: Compose files for one node and for a cluster, each as unprivileged as its network allows, on Debian 13

- **Status:** Accepted, extends [ADR 0027](0027-packages-and-container-image.md), extended by [ADR 0037](0037-helm-chart.md)
- **Date:** 2026-10-10

## Context

[ADR 0027](0027-packages-and-container-image.md) ships a container image that starts as root,
binds port 53, then switches to uid 65532 and gives up every capability, because runtimes
disagree on whether an unprivileged process may bind a port below 1024: Docker (since 20.10) sets
`net.ipv4.ip_unprivileged_port_start` to 0 in a container's network namespace, Podman leaves it
at 1024 (checked on Podman 6.0, 2026-10-10). The install guide documents a `docker run` line.
Most people who self-host a DNS server in containers use Compose instead, and a Compose file
written by hand usually keeps the runtime's defaults: root, with the default capability set, for
as long as the container runs.

A cluster ([ADR 0031](0031-raft-clustering.md)) adds three constraints. The floating IP's helper,
`goethite vrrp`, needs `CAP_NET_ADMIN` and `CAP_NET_RAW` on the host's own interface. A member that
starts a cluster gives the others its `listen` address. And Docker gives a process that is not
root no capabilities at all, whatever `cap_add` says; Podman passes them as ambient capabilities,
Docker does not (moby#26979 was reverted).

The image's base, `gcr.io/distroless/cc-debian12`, was deprecated by the distroless project on
1 September 2026, after Debian 12 left regular security support; its images are no longer
rebuilt with security fixes.

## Decision

**`deploy/container/compose.yaml` runs one node as 65532 from the start, with no capabilities.
`deploy/container/cluster/` has one Compose project per kind of member, each on its own machine: a
DNS node starts as root on the host's network with only the capabilities it needs, the witness
runs as 65532 with none. All of them set `no-new-privileges` and a read-only root file system. The
image moves to `gcr.io/distroless/cc-debian13`.**

One node (`compose.yaml`):

- **Never root.** Compose sets `net.ipv4.ip_unprivileged_port_start = 53` for the container's own
  network namespace on any runtime, so the difference ADR 0027 works around does not arise; the
  host's setting is untouched. The image config's `server.user = "nonroot"` matches the user it
  already runs as.
- **`ulimits: nofile: 65536`**, the systemd unit's `LimitNOFILE`: every UDP query in flight
  forwards over its own socket, and runtime defaults run from 1024 to 1048576.
- **The image's own config** until the user mounts one; the line for that, the API port (on
  loopback) and a host-network variant, for runtimes that show every client as one address and so
  put the whole network under one client's rate limit, are there as comments.

A cluster (`cluster/node/`, `cluster/witness/`):

- **A node's two services use the host's network.** The floating IP must go on the host's
  interface, VRRP and ARP must reach the other node directly, and the members must give each other
  their hosts' addresses. The sysctl cannot be set there, so goethite starts as root with
  `NET_BIND_SERVICE`, `SETUID` and `SETGID`, as ADR 0027's image does, and `goethite vrrp` as root
  with `NET_ADMIN` and `NET_RAW`, keeping only `NET_ADMIN` once its sockets are open.
- **`goethite vrrp` depends on goethite with `restart: true`**, as `PartOf=` ties the units: Compose
  stops it first when it recreates goethite, which hands the floating IP over at once.
- **The witness runs as 65532** in a network namespace of its own, with the cluster port
  published and `listen = "0.0.0.0:8054"`: only a member that starts a cluster gives its `listen`
  address to the others, and a witness never does.
- **Keys belong to root, group 65532, mode 0640.** goethite reads them before dropping privileges:
  as root without `CAP_DAC_OVERRIDE` on the nodes, as 65532 on the witness.
- **Example configs per member** (`dns1.toml`, `dns2.toml`, `witness.toml`), with the HA guide's
  addresses and the store's path set: without `[store] path`, the store would go beside the
  config file, which is read-only in these containers.

Every Compose file uses **the minor version's tag** (`0.5`): patch releases arrive, the next
minor does not, since before 1.0 a minor may change the config format. `cargo xtask versions`
fails when a `compose.yaml` under `deploy/` runs another, so none falls behind a release.

The image still starts as root (ADR 0027). It also gains:

- **Debian 13** (glibc 2.41; releases still need no glibc newer than 2.34), by digest.
- **The Containerfile syntax pinned by digest** (`docker/dockerfile:1.27`), so the build no longer
  depends on the frontend built into whichever BuildKit runs it. Renovate moves both digests.
- **The usual OCI labels** (title, version, revision, URL, documentation), with the version and
  commit passed in by `cargo xtask image` as the last instructions. `cargo xtask image` also
  copies every label onto a multi-architecture index as an annotation: ghcr.io shows the
  description it finds there, not the images' labels.
- **No build cache** in `cargo xtask image`: a layer cached from another commit's build kept that
  commit's older timestamps (`rewrite-timestamp` only lowers them), so rebuilding a release on a
  machine that had built something else gave different bytes. Nothing in the image compiles, so a
  fresh build takes seconds.

## Alternatives considered

- **`USER 65532` in the image:** `podman run` and Kubernetes would fail to bind port 53 without
  the sysctl; ADR 0027's reason still holds.
- **The single node starting as root, with `cap_drop: [ALL]` and `cap_add` of three
  capabilities:** works on every runtime without the sysctl, but holds root and three
  capabilities until goethite drops them. Kept for host networking, where it is the only way.
- **`goethite vrrp` as 65532 with `cap_add`:** works on Podman, gets no capabilities on Docker.
- **A whole cluster in one Compose file on one host:** good for a demonstration, but it goes down
  with that host; the chaos lab already shows clustering on one machine.
- **One cluster file with a profile per member kind:** every command on a machine would need the
  profile; a directory per kind needs nothing.
- **The witness on the host's network:** works, but needs nothing that a namespace of its own and
  one published port do not give it.
- **The `latest` tag:** an unattended minor upgrade could stop at a config format change.
- **A `HEALTHCHECK`:** the image has no shell or HTTP client, and `goethite --version` (which
  some images use) starts a new process and says nothing about the running one. A subcommand that
  asks the running goethite is in the backlog.
- **Mounting a config directory over `/etc/goethite`:** hides the image's local lists directory.
  goethite reads its config file once at start, so one file mounted read-only is enough.

## Consequences

- People who use the Compose files run goethite with the least the image and their network
  allow, without having to know the flags; `docker run` keeps ADR 0027's root start unless given
  the same options.
- `goethite vrrp` warns in every container that it runs as root, which it does, with
  `CAP_NET_ADMIN` alone. A way for it to switch to an unprivileged user and keep that capability
  is in the backlog.
- A node in a container cannot upgrade in place: recreating it stops its answers for a second or
  two, while the other node answers on the floating IP.
- A minor release bumps three more files, and `cargo xtask versions` says so.
- The image no longer matches one built from the same tarballs on Debian 12: reproducibility
  holds per commit, as before.
- Building the image now pulls the syntax image from Docker Hub, as the build image already pulls
  Rust and Node.js from there.
- Revisit when goethite gets a health subcommand (a `HEALTHCHECK` and a Compose `healthcheck`),
  or when distroless deprecates Debian 13.
