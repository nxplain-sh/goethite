//! Running the floating IP on Linux: the sockets, and the loop that feeds
//! the state machine and carries out what it decides.

use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

use rustix::net::RecvFlags;
use socket2::{Domain, InterfaceIndexOrAddress, Protocol, SockRef, Socket, Type};
use tokio::io::unix::AsyncFd;
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use super::arp::ArpSocket;
use super::machine::{Action, Machine, Settings, State};
use super::netlink::{ARPHRD_ETHER, Netlink};
use super::packet::{self, GROUP, PROTOCOL, TTL};
use super::{Ignored, VrrpConfig, VrrpError, check};

/// Room for any advertisement: a 60-byte IPv4 header and 255 addresses
/// take 1,088 bytes.
const BUFFER_LEN: usize = 2048;

/// Gratuitous ARP announcements after taking the address over, one a
/// second: a switch that missed the first hears the next.
const ANNOUNCEMENTS: u8 = 3;

/// How often the same kind of warning is logged at most.
const WARN_EVERY: Duration = Duration::from_secs(60);

/// `IPTOS_PREC_INTERNETCONTROL`: advertisements are network control
/// traffic, queued first on congested links.
const TOS_NETWORK_CONTROL: u32 = 0xc0;

/// The floating IP on this node, with its sockets open.
#[derive(Debug)]
pub struct Vrrp {
    config: VrrpConfig,
    index: u32,
    source: Ipv4Addr,
    hardware: Option<[u8; 6]>,
    send: Socket,
    receive: Socket,
    netlink: Netlink,
    arp: Option<ArpSocket>,
}

fn io_error(what: impl Into<String>) -> impl FnOnce(io::Error) -> VrrpError {
    let what = what.into();
    move |source| VrrpError::Io { what, source }
}

impl Vrrp {
    /// Opens the sockets, and removes the floating IP if an earlier run
    /// left it behind. Needs `CAP_NET_RAW` and `CAP_NET_ADMIN`; afterwards
    /// [`Vrrp::run`] needs only `CAP_NET_ADMIN`.
    ///
    /// # Errors
    ///
    /// If the interface does not exist, the peer cannot be reached through
    /// it, or a socket cannot be opened (usually a missing capability).
    pub fn open(config: VrrpConfig) -> Result<Self, VrrpError> {
        let interface = config.interface.clone();
        let probe = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .map_err(io_error("cannot open a socket"))?;
        let index = rustix::net::netdevice::name_to_index(&probe, &interface)
            .map_err(|err| io_error(format!("no interface {interface:?}"))(err.into()))?;
        let mut netlink = Netlink::open().map_err(io_error("cannot open a netlink socket"))?;
        let left_over = netlink
            .remove(index, config.address)
            .map_err(io_error(format!(
                "cannot remove {} from {interface} (goethite vrrp needs CAP_NET_ADMIN)",
                config.address
            )))?;
        if left_over {
            info!(
                address = %config.address,
                %interface,
                "removed the floating IP an earlier run left behind"
            );
        }

        // The address this node advertises from: the one the kernel picks
        // to reach the peer through the interface.
        SockRef::from(&probe)
            .bind_device(Some(interface.as_bytes()))
            .map_err(io_error(format!(
                "cannot bind to {interface} (goethite vrrp needs CAP_NET_RAW)"
            )))?;
        probe.connect((config.peer, 9)).map_err(io_error(format!(
            "the peer {} cannot be reached through {interface}",
            config.peer
        )))?;
        let source = match probe.local_addr() {
            Ok(SocketAddr::V4(local)) => *local.ip(),
            Ok(SocketAddr::V6(_)) => {
                return Err(VrrpError::Io {
                    what: format!("{interface} has no IPv4 address"),
                    source: io::Error::other("an IPv6 source address"),
                });
            }
            Err(err) => return Err(io_error(format!("{interface} has no IPv4 address"))(err)),
        };

        let link = netlink.link(index).map_err(io_error(format!(
            "cannot read {interface}'s hardware address"
        )))?;
        let (hardware, arp) = match link.hardware {
            Some(hardware) if link.kind == ARPHRD_ETHER => {
                let arp = ArpSocket::open(index).map_err(io_error(
                    "cannot open a packet socket for ARP (goethite vrrp needs CAP_NET_RAW)",
                ))?;
                (Some(hardware), Some(arp))
            }
            _ => {
                warn!(
                    %interface,
                    "not an Ethernet interface: no gratuitous ARP after taking the floating IP"
                );
                (None, None)
            }
        };
        let send = sender(&interface, source).map_err(io_error(
            "cannot open the socket advertisements are sent on (goethite vrrp needs CAP_NET_RAW)",
        ))?;
        let receive = receiver(&interface, index).map_err(io_error(
            "cannot open the socket advertisements are received on",
        ))?;
        Ok(Self {
            config,
            index,
            source,
            hardware,
            send,
            receive,
            netlink,
            arp,
        })
    }

    /// This node's address on the interface, which it advertises from.
    pub fn source(&self) -> Ipv4Addr {
        self.source
    }

    /// Runs until `shutdown` completes, taking the address when this node
    /// should hold it. `health` says whether the DNS server answers; until
    /// it first says so, this node stays out of the way. On the way out a
    /// master hands over at once (priority 0) and removes the address.
    ///
    /// # Errors
    ///
    /// If the address cannot be added; it is removed again first.
    pub async fn run(
        self,
        mut health: watch::Receiver<bool>,
        shutdown: impl Future<Output = ()>,
    ) -> Result<(), VrrpError> {
        let Self {
            config,
            index,
            source,
            hardware,
            send,
            receive,
            netlink,
            arp,
        } = self;
        let receive = AsyncFd::new(receive).map_err(io_error("cannot watch the VRRP socket"))?;
        let settings = Settings {
            priority: config.priority,
            interval: config.interval,
            preempt: config.preempt,
            address: source,
        };
        info!(
            interface = %config.interface,
            address = %config.address,
            source = %source,
            peer = %config.peer,
            router_id = config.router_id,
            priority = config.priority,
            "VRRP started; waiting for goethite to answer its first health check"
        );
        let mut node = Node {
            destination: if config.unicast { config.peer } else { GROUP },
            config,
            index,
            source,
            hardware,
            send,
            netlink,
            arp,
            machine: Machine::new(settings),
            announcements: Announcements::default(),
            warnings: Throttle::default(),
        };
        let mut buffer = vec![0; BUFFER_LEN];
        let mut health_open = true;
        tokio::pin!(shutdown);
        let result = loop {
            let before = node.machine.state();
            let actions = tokio::select! {
                () = &mut shutdown => break Ok(()),
                changed = health.changed(), if health_open => {
                    health_open = changed.is_ok();
                    let healthy = health_open && *health.borrow_and_update();
                    node.machine.health(healthy, Instant::now())
                }
                () = sleep_until(node.machine.deadline()) => node.machine.tick(Instant::now()),
                () = sleep_until(node.announcements.next) => {
                    node.announce(Instant::now());
                    Vec::new()
                }
                readable = receive.readable() => match readable {
                    Ok(mut guard) => match guard.try_io(|socket| {
                        rustix::net::recv(socket.get_ref(), &mut buffer[..], RecvFlags::TRUNC)
                            .map_err(io::Error::from)
                    }) {
                        Ok(Ok((len, full))) if full <= len => {
                            node.receive(buffer.get(..len).unwrap_or_default(), Instant::now())
                        }
                        Ok(Ok(_)) => {
                            debug!("ignored an oversized VRRP packet");
                            Vec::new()
                        }
                        Ok(Err(err)) => {
                            node.warn(|| warn!(%err, "cannot receive VRRP advertisements"));
                            Vec::new()
                        }
                        Err(_would_block) => Vec::new(),
                    },
                    Err(err) => break Err(io_error("cannot watch the VRRP socket")(err)),
                },
            };
            // The new state first, then what it takes.
            node.log_change(before);
            if let Err(err) = node.apply(&actions) {
                break Err(err);
            }
        };
        let actions = node.machine.shutdown();
        if let Err(err) = node.apply(&actions) {
            error!(%err, "cannot hand the floating IP over cleanly");
        }
        // Whatever the state: never leave the address behind.
        node.release();
        result
    }
}

/// The socket advertisements go out on, from `source`, with a TTL of 255.
fn sender(interface: &str, source: Ipv4Addr) -> io::Result<Socket> {
    let socket = vrrp_socket()?;
    socket.bind_device(Some(interface.as_bytes()))?;
    // Fixes the source address, which the checksum covers.
    socket.bind(&SocketAddrV4::new(source, 0).into())?;
    socket.set_multicast_if_v4(&source)?;
    socket.set_multicast_ttl_v4(u32::from(TTL))?;
    socket.set_multicast_loop_v4(false)?;
    socket.set_ttl_v4(u32::from(TTL))?;
    socket.set_tos_v4(TOS_NETWORK_CONTROL)?;
    // It never reads: the smallest buffer for what arrives for `source`.
    socket.set_recv_buffer_size(0)?;
    Ok(socket)
}

/// The socket advertisements arrive on: the group's and this node's, on
/// `interface` only.
fn receiver(interface: &str, index: u32) -> io::Result<Socket> {
    let socket = vrrp_socket()?;
    socket.bind_device(Some(interface.as_bytes()))?;
    socket.join_multicast_v4_n(&GROUP, &InterfaceIndexOrAddress::Index(index))?;
    Ok(socket)
}

fn vrrp_socket() -> io::Result<Socket> {
    let socket = Socket::new(
        Domain::IPV4,
        Type::RAW,
        Some(Protocol::from(i32::from(PROTOCOL))),
    )?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
        None => std::future::pending().await,
    }
}

/// The gratuitous ARP announcements still to send.
#[derive(Debug, Default)]
struct Announcements {
    left: u8,
    next: Option<Instant>,
}

/// Logs a kind of warning at most once per [`WARN_EVERY`].
#[derive(Debug, Default)]
struct Throttle {
    last: Option<Instant>,
}

impl Throttle {
    fn allow(&mut self, now: Instant) -> bool {
        if self
            .last
            .is_some_and(|last| now.saturating_duration_since(last) < WARN_EVERY)
        {
            return false;
        }
        self.last = Some(now);
        true
    }
}

/// Everything the loop works with.
struct Node {
    config: VrrpConfig,
    index: u32,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    hardware: Option<[u8; 6]>,
    send: Socket,
    netlink: Netlink,
    arp: Option<ArpSocket>,
    machine: Machine,
    announcements: Announcements,
    warnings: Throttle,
}

impl Node {
    fn warn(&mut self, log: impl FnOnce()) {
        if self.warnings.allow(Instant::now()) {
            log();
        }
    }

    fn receive(&mut self, packet: &[u8], now: Instant) -> Vec<Action> {
        let received = match packet::parse(packet) {
            Ok(received) => received,
            // Other VRRP versions and protocols share the socket.
            Err(err) => {
                debug!(%err, "ignored a VRRP packet");
                return Vec::new();
            }
        };
        match check(&self.config, self.source, &received) {
            Ok(heard) => self.machine.heard(heard, now),
            Err(Ignored::OtherRouter | Ignored::Own) => Vec::new(),
            Err(ignored) => {
                self.warn(|| warn!(reason = %ignored, "ignored a VRRP advertisement"));
                Vec::new()
            }
        }
    }

    fn apply(&mut self, actions: &[Action]) -> Result<(), VrrpError> {
        for &action in actions {
            match action {
                Action::Advertise(priority) => self.advertise(priority),
                Action::Take => {
                    self.netlink
                        .add(self.index, self.config.address)
                        .map_err(io_error(format!(
                            "cannot add the floating IP {} to {}",
                            self.config.address, self.config.interface
                        )))?;
                    info!(
                        address = %self.config.address,
                        interface = %self.config.interface,
                        "this node holds the floating IP now"
                    );
                    self.announcements = Announcements {
                        left: ANNOUNCEMENTS,
                        next: None,
                    };
                    self.announce(Instant::now());
                }
                Action::Release => self.release(),
            }
        }
        Ok(())
    }

    fn advertise(&mut self, priority: u8) {
        let packet = packet::encode(
            self.config.router_id,
            priority,
            self.config.interval,
            &[self.config.address],
            self.source,
            self.destination,
        );
        let to = SocketAddrV4::new(self.destination, 0).into();
        if let Err(err) = self.send.send_to(&packet, &to) {
            self.warn(|| warn!(%err, "cannot send a VRRP advertisement"));
        }
    }

    fn announce(&mut self, now: Instant) {
        let left = self.announcements.left;
        self.announcements = Announcements {
            left: left.saturating_sub(1),
            next: (left > 1)
                .then(|| now.checked_add(Duration::from_secs(1)))
                .flatten(),
        };
        if left == 0 {
            return;
        }
        let (Some(arp), Some(hardware)) = (&self.arp, self.hardware) else {
            return;
        };
        if let Err(err) = arp.announce(hardware, self.config.address) {
            self.warn(|| warn!(%err, "cannot send a gratuitous ARP announcement"));
        }
    }

    fn release(&mut self) {
        self.announcements = Announcements::default();
        match self.netlink.remove(self.index, self.config.address) {
            Ok(true) => info!(
                address = %self.config.address,
                interface = %self.config.interface,
                "released the floating IP"
            ),
            Ok(false) => {}
            Err(err) => error!(
                %err,
                address = %self.config.address,
                "cannot remove the floating IP"
            ),
        }
    }

    fn log_change(&self, before: State) {
        let after = self.machine.state();
        if after == before {
            return;
        }
        match after {
            State::Backup if before == State::Fault => {
                info!("goethite answers its health checks; standing by as backup");
            }
            State::Backup => info!("the peer has priority; standing by as backup"),
            State::Master => info!("the peer is silent or has lower priority; taking over"),
            State::Fault => {
                warn!("goethite fails its health checks; leaving the floating IP to the peer");
            }
        }
    }
}
