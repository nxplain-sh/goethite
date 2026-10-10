# ADR 0037: A Helm chart for one node on Kubernetes, unprivileged by default

- **Status:** Accepted, extends [ADR 0036](0036-compose-files.md)
- **Date:** 2026-10-10

## Context

[ADR 0027](0027-packages-and-container-image.md) ships a container image, and
[ADR 0036](0036-compose-files.md) Compose files, neither of which is how a Kubernetes user deploys
an application: they expect a Helm chart. Kubernetes also changes three of ADR 0036's assumptions.
A pod's security context sets sysctls in its own network namespace, and
`net.ipv4.ip_unprivileged_port_start` has been a safe sysctl since Kubernetes 1.22, so the
unprivileged single-node Compose shape (65532, no capabilities) carries over. A host-network pod
shares the node's network namespace, so it cannot set that sysctl and needs the root start with
three capabilities that ADR 0036's cluster files use. And a floating IP through VRRP is not a
Kubernetes concept: surviving a node failure there means a Service over nodes that each answer,
which is a different shape from the Raft-and-VRRP cluster goethite has today.

## Decision

**`deploy/helm/goethite/` deploys one node: a Deployment (one replica, `Recreate`), a Service for
DNS on port 53 (UDP and TCP), and the store and the downloaded lists on a
PersistentVolumeClaim. The chart runs as unprivileged as its network shape allows, and
`cargo xtask versions` checks what it carries.**

- **Default: no host network.** The pod runs as 65532 with no capabilities, a
  `net.ipv4.ip_unprivileged_port_start: 53` pod sysctl, `fsGroup` so the volume belongs to the
  user, a read-only root file system, `RuntimeDefault` seccomp and no service-account token: the
  single-node Compose shape. In-cluster clients use the Service; with `LoadBalancer`, the chart
  sets `externalTrafficPolicy: Local` so goethite still sees client addresses.
- **`hostNetwork: true`: the cluster Compose shape.** The pod starts as root with
  `NET_BIND_SERVICE`, `SETUID` and `SETGID`, because a host-network pod cannot set the sysctl; the
  image binds port 53, switches to 65532 and gives them up. Every node answers on port 53, the
  rest of the network can point at it, and goethite sees each client's own address, which groups,
  the query log and the per-client rate limit need.
- **`Recreate`, one replica.** The store is one redb file on one `ReadWriteOnce` claim; two pods
  must never write it. An upgrade stops DNS for a second or two, as a container restart does.
- **Config is a ConfigMap only when the user has one.** An empty `config` leaves the image's own
  `goethite.toml` (Quad9 over DNS over TLS, the recommended lists) in place; otherwise the chart
  mounts the user's file over it, and a checksum annotation rolls the pod out when it changes.
- **The image tag is the chart's `appVersion`** (the newest release of this minor version, as
  the Compose files' tag is), and the chart's `version` is the workspace version. `cargo xtask
  versions` fails when either drifts (docs/releases.md).
- **CI lints the chart and renders its shapes** (`helm lint` and three `helm template` runs) in a
  `helm` job; Helm ships with the runner image.

Not in the chart: the witness, VRRP and a cluster. On Kubernetes they need a shape of their own
(replicas behind one address, no floating IP), which this ADR does not decide; the install guide
points at the Compose files and packages for a cluster until then.

## Alternatives considered

- **A Kubernetes operator:** reconciles a bigger surface (lists, rules, groups) than one node's
  Deployment, and a chart covers the deployment itself; revisit with cluster support.
- **Default `hostNetwork: true`:** every install would answer for a whole network, but every node
  would give up port 53 and the pod would start as root by default, where the sysctl does the job
  unprivileged. A value flips the default for people who need it.
- **Publishing the chart to an OCI registry or Artifact Hub first:** release automation for the
  chart does not exist, and installing from the repository path works; both are in the backlog.
- **A StatefulSet:** one replica and one claim make it no better than a Deployment, and its stable
  identity is unused.
- **A subchart per cluster member:** follows once a Kubernetes cluster shape exists; today it
  would invent that shape under the pressure of a first chart.
- **Probes on the API port:** the API answers on loopback only until a token is configured, and
  the data plane must count as up while the control plane is down; the chart probes port 53 with
  a TCP connect, since the image has no health subcommand yet (ADR 0036).

## Consequences

- Kubernetes users install with `helm install goethite deploy/helm/goethite`. Nothing is
  published yet, so the chart is installed from the repository; a chart repository is in the
  backlog.
- A release bumps `Chart.yaml` in two places; `cargo xtask versions` and the `versions` CI job
  enforce it.
- Clustering on Kubernetes is future work; until it exists the chart is one node, and the HA
  guide's Compose files serve the rest.
- The default install needs no node configuration: no port 53 held on the nodes, no privileged
  container.
