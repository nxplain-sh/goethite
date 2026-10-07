//! Binding the listen sockets.
//!
//! Sockets are bound with the standard library (through socket2) rather than
//! tokio, so the binary can bind them before the async runtime starts and
//! before it drops root privileges, and hand them to [`crate::Server::new`]
//! afterwards.
//!
//! On Linux every listen address gets several UDP sockets bound with
//! `SO_REUSEPORT`, by default one per CPU core: the kernel spreads incoming
//! datagrams over them by source address and port, so receiving scales with
//! the cores instead of funnelling through one socket. Other platforms get a
//! single UDP socket per address. IPv6 sockets are IPv6-only, so `0.0.0.0`
//! and `[::]` can be listened on side by side.

use std::io;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::num::NonZeroUsize;

use socket2::{Domain, Protocol, Socket, Type};

use crate::{ServerConfig, ServerError, Transport};

/// The most UDP sockets per listen address.
pub const MAX_UDP_SOCKETS: usize = 64;

/// The most listen addresses.
pub const MAX_LISTEN_ADDRESSES: usize = 16;

/// Pending TCP connections the kernel queues before `accept`.
const TCP_BACKLOG: i32 = 1024;

/// One UDP socket per available CPU core on Linux (at most
/// [`MAX_UDP_SOCKETS`]), one elsewhere.
pub fn default_udp_sockets() -> usize {
    if cfg!(target_os = "linux") {
        std::thread::available_parallelism()
            .map_or(1, NonZeroUsize::get)
            .min(MAX_UDP_SOCKETS)
    } else {
        1
    }
}

/// The sockets of one listen address.
#[derive(Debug)]
pub(crate) struct Bound {
    pub(crate) udp: Vec<UdpSocket>,
    pub(crate) tcp: TcpListener,
}

/// Bound but not yet serving sockets for every listen address.
#[derive(Debug)]
pub struct Listeners {
    pub(crate) addresses: Vec<Bound>,
}

impl Listeners {
    /// Binds a TCP listener and [`ServerConfig::udp_sockets`] UDP sockets
    /// (one on platforms other than Linux) on each address in
    /// [`ServerConfig::listen`]. Does not need an async runtime.
    ///
    /// # Errors
    ///
    /// [`ServerError::NoListenAddresses`] and
    /// [`ServerError::TooManyListenAddresses`] for an unusable address list,
    /// and [`ServerError::Bind`] if a socket cannot be bound.
    pub fn bind(config: &ServerConfig) -> Result<Self, ServerError> {
        if config.listen.is_empty() {
            return Err(ServerError::NoListenAddresses);
        }
        if config.listen.len() > MAX_LISTEN_ADDRESSES {
            return Err(ServerError::TooManyListenAddresses(config.listen.len()));
        }
        let udp_sockets = if cfg!(target_os = "linux") {
            config.udp_sockets.clamp(1, MAX_UDP_SOCKETS)
        } else {
            1
        };
        let addresses = config
            .listen
            .iter()
            .map(|&addr| bind_address(addr, udp_sockets))
            .collect::<Result<_, _>>()?;
        Ok(Self { addresses })
    }

    /// The local address of each listen address's UDP sockets.
    ///
    /// # Errors
    ///
    /// Returns the operating system's error if an address is unavailable.
    pub fn udp_local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.addresses
            .iter()
            .filter_map(|bound| bound.udp.first())
            .map(UdpSocket::local_addr)
            .collect()
    }

    /// The local address of each TCP listener.
    ///
    /// # Errors
    ///
    /// Returns the operating system's error if an address is unavailable.
    pub fn tcp_local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.addresses
            .iter()
            .map(|bound| bound.tcp.local_addr())
            .collect()
    }
}

fn bind_address(addr: SocketAddr, udp_sockets: usize) -> Result<Bound, ServerError> {
    let error = |transport| {
        move |source| ServerError::Bind {
            transport,
            addr,
            source,
        }
    };
    let reuse_port = udp_sockets > 1;
    let first = udp_socket(addr, reuse_port).map_err(error(Transport::Udp))?;
    // With port 0 the first socket picks the port; the others join it.
    let actual = first.local_addr().map_err(error(Transport::Udp))?;
    let mut udp = Vec::with_capacity(udp_sockets);
    udp.push(first);
    for _ in 1..udp_sockets {
        udp.push(udp_socket(actual, reuse_port).map_err(error(Transport::Udp))?);
    }
    let tcp = tcp_listener(addr).map_err(error(Transport::Tcp))?;
    Ok(Bound { udp, tcp })
}

fn socket(addr: SocketAddr, kind: Type, protocol: Protocol) -> io::Result<Socket> {
    let socket = Socket::new(Domain::for_address(addr), kind, Some(protocol))?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    // tokio needs non-blocking sockets.
    socket.set_nonblocking(true)?;
    Ok(socket)
}

fn udp_socket(addr: SocketAddr, reuse_port: bool) -> io::Result<UdpSocket> {
    let socket = socket(addr, Type::DGRAM, Protocol::UDP)?;
    // Only set when there are several sockets: it would also let another
    // process of the same user bind the port and receive part of the queries.
    #[cfg(target_os = "linux")]
    if reuse_port {
        socket.set_reuse_port(true)?;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = reuse_port;
    socket.bind(&addr.into())?;
    Ok(socket.into())
}

fn tcp_listener(addr: SocketAddr) -> io::Result<TcpListener> {
    let socket = socket(addr, Type::STREAM, Protocol::TCP)?;
    // As the standard library does: restarting must not wait for TIME_WAIT.
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(TCP_BACKLOG)?;
    Ok(socket.into())
}
