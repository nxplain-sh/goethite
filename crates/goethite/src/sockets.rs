//! The node's listening sockets: bound here, taken over from the previous
//! goethite on an upgrade, or given back by systemd after a restart.
//!
//! Every socket also gets a name and a duplicate kept for the life of the
//! process. The duplicates are what a new goethite receives on an upgrade
//! and what goes into systemd's file-descriptor store. Names follow the
//! config file:
//!
//! - `dns-udp-<n>-<i>` and `dns-tcp-<n>` for the `n`th `[server] listen`
//!   address;
//! - `dns-dot-<n>` and `dns-doh-<n>` for the `n`th `[server.tls] dot` and
//!   `doh` address;
//! - `api-<n>` for the `n`th `[api] listen` address;
//! - `cluster` for the cluster listener.
//!
//! systemd's names may not contain colons, hence numbers, not addresses.
//! Sockets taken over are checked against the config file's addresses
//! before they are used.

use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use anyhow::{Context, Result, bail};
use goethite_api::ApiListeners;
use goethite_server::{Listeners, MAX_UDP_SOCKETS};
use socket2::{SockRef, Type};
use tracing::warn;

use crate::config::Config;

/// Every listening socket of the node.
pub struct Sockets {
    dns: Option<Listeners>,
    api: Vec<TcpListener>,
    cluster: Option<TcpListener>,
    named: Vec<(String, OwnedFd)>,
}

impl Sockets {
    /// Binds every socket the config file asks for.
    ///
    /// # Errors
    ///
    /// If one cannot be bound.
    pub fn bind(config: &Config) -> Result<Self> {
        let dns = Listeners::bind(&config.server_config())?;
        let api = if config.api.enabled {
            config
                .api
                .listen
                .iter()
                .map(|&addr| bind_tcp(addr, "the API"))
                .collect::<Result<_>>()?
        } else {
            Vec::new()
        };
        let cluster = config
            .cluster
            .as_ref()
            .map(|cluster| bind_tcp(cluster.listen, "the cluster listener"))
            .transpose()?;
        Self::new(dns, api, cluster)
    }

    /// Takes over sockets bound by an earlier goethite or by systemd, by
    /// name, checking each against the config file. Sockets the config no
    /// longer asks for are closed.
    ///
    /// # Errors
    ///
    /// If a socket the config asks for is missing, or is not what its name
    /// says. Listen addresses cannot change without a restart.
    pub fn adopt(config: &Config, given: Vec<(String, OwnedFd)>) -> Result<Self> {
        let mut by_name: HashMap<String, OwnedFd> = given.into_iter().collect();
        let mut take = |name: &str| {
            by_name.remove(name).with_context(|| {
                format!(
                    "the socket {name} was not handed over: the listen addresses changed, \
                     which needs a restart"
                )
            })
        };
        let server = config.server_config();
        let mut addresses = Vec::with_capacity(server.listen.len());
        for (n, &addr) in server.listen.iter().enumerate() {
            let mut udp = Vec::new();
            for i in 0..MAX_UDP_SOCKETS {
                match take(&format!("dns-udp-{n}-{i}")) {
                    Ok(fd) => udp.push(UdpSocket::from(checked(fd, Type::DGRAM, addr)?)),
                    Err(_) if i > 0 => break,
                    Err(err) => return Err(err),
                }
            }
            let tcp =
                TcpListener::from(checked(take(&format!("dns-tcp-{n}"))?, Type::STREAM, addr)?);
            addresses.push((udp, tcp));
        }
        let mut encrypted = |prefix: &str, list: &[SocketAddr]| -> Result<Vec<TcpListener>> {
            list.iter()
                .enumerate()
                .map(|(n, &addr)| {
                    let fd = take(&format!("{prefix}-{n}"))?;
                    Ok(TcpListener::from(checked(fd, Type::STREAM, addr)?))
                })
                .collect()
        };
        let dot = encrypted("dns-dot", &server.dot)?;
        let doh = encrypted("dns-doh", &server.doh)?;
        let mut api = Vec::new();
        if config.api.enabled {
            for (n, &addr) in config.api.listen.iter().enumerate() {
                let fd = take(&format!("api-{n}"))?;
                api.push(TcpListener::from(checked(fd, Type::STREAM, addr)?));
            }
        }
        let cluster = match &config.cluster {
            Some(cluster) => Some(TcpListener::from(checked(
                take("cluster")?,
                Type::STREAM,
                cluster.listen,
            )?)),
            None => None,
        };
        for name in by_name.keys() {
            warn!(
                name,
                "a socket handed over is not in the config file any more; closing it"
            );
        }
        let dns =
            Listeners::from_sockets(addresses, dot, doh).context("the DNS sockets handed over")?;
        Self::new(dns, api, cluster)
    }

    fn new(dns: Listeners, api: Vec<TcpListener>, cluster: Option<TcpListener>) -> Result<Self> {
        let mut named = Vec::new();
        for (n, (udp, tcp)) in dns.sockets().enumerate() {
            for (i, socket) in udp.iter().enumerate() {
                named.push((format!("dns-udp-{n}-{i}"), duplicate(socket)?));
            }
            named.push((format!("dns-tcp-{n}"), duplicate(tcp)?));
        }
        for (n, listener) in dns.dot().iter().enumerate() {
            named.push((format!("dns-dot-{n}"), duplicate(listener)?));
        }
        for (n, listener) in dns.doh().iter().enumerate() {
            named.push((format!("dns-doh-{n}"), duplicate(listener)?));
        }
        for (n, listener) in api.iter().enumerate() {
            named.push((format!("api-{n}"), duplicate(listener)?));
        }
        if let Some(listener) = &cluster {
            named.push(("cluster".to_owned(), duplicate(listener)?));
        }
        Ok(Self {
            dns: Some(dns),
            api,
            cluster,
            named,
        })
    }

    /// The DNS sockets, for the server, which owns them from then on.
    pub fn take_dns(&mut self) -> Option<Listeners> {
        self.dns.take()
    }

    /// The API's sockets, if it is on: fresh duplicates, so the API can be
    /// started again after a stop.
    ///
    /// # Errors
    ///
    /// If a socket cannot be duplicated.
    pub fn api_listeners(&self) -> Result<Option<ApiListeners>> {
        if self.api.is_empty() {
            return Ok(None);
        }
        let listeners = self
            .api
            .iter()
            .map(TcpListener::try_clone)
            .collect::<std::io::Result<_>>()?;
        Ok(Some(ApiListeners::from_listeners(listeners)?))
    }

    /// The cluster listener, if there is one, as a fresh duplicate.
    ///
    /// # Errors
    ///
    /// If it cannot be duplicated.
    pub fn cluster_listener(&self) -> Result<Option<ApiListeners>> {
        match &self.cluster {
            Some(listener) => Ok(Some(ApiListeners::from_listeners(vec![
                listener.try_clone()?,
            ])?)),
            None => Ok(None),
        }
    }

    /// Every socket with its name, to hand over or store.
    pub fn named(&self) -> impl Iterator<Item = (&str, BorrowedFd<'_>)> {
        self.named
            .iter()
            .map(|(name, fd)| (name.as_str(), fd.as_fd()))
    }
}

/// A TCP listener for the API or the cluster.
fn bind_tcp(addr: SocketAddr, what: &str) -> Result<TcpListener> {
    let listener =
        TcpListener::bind(addr).with_context(|| format!("cannot bind {what} on {addr}"))?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// A duplicate of `socket` to keep: the original goes to its server.
fn duplicate(socket: &impl AsFd) -> Result<OwnedFd> {
    socket
        .as_fd()
        .try_clone_to_owned()
        .context("cannot duplicate a listening socket")
}

/// `fd`, once it is a socket of `kind` bound to `expected` (any port if the
/// config says port 0).
fn checked(fd: OwnedFd, kind: Type, expected: SocketAddr) -> Result<OwnedFd> {
    let socket = SockRef::from(&fd);
    let actual = socket
        .r#type()
        .context("a socket handed over is not a socket")?;
    if actual != kind {
        bail!("a socket handed over for {expected} is of the wrong kind");
    }
    let local = socket
        .local_addr()
        .ok()
        .and_then(|addr| addr.as_socket())
        .context("a socket handed over has no address")?;
    if local.ip() != expected.ip() || (expected.port() != 0 && local.port() != expected.port()) {
        bail!("a socket handed over for {expected} is bound to {local}");
    }
    Ok(fd)
}

/// The sockets systemd passed to this process (`LISTEN_FDS`), by name.
/// Call it first thing, before any file is opened. Empty if systemd passed
/// none, or passed them to another process.
#[cfg(target_os = "linux")]
#[allow(
    unsafe_code,
    reason = "adopting descriptors systemd passes by number; see the SAFETY comment"
)]
pub fn take_systemd_fds() -> Vec<(String, OwnedFd)> {
    use std::os::fd::FromRawFd as _;

    /// systemd's first passed descriptor (`SD_LISTEN_FDS_START`).
    const FIRST: i32 = 3;
    /// The most sockets taken from systemd: more than goethite ever stores.
    const MAX_SYSTEMD_FDS: usize = 4096;

    let for_us = std::env::var("LISTEN_PID")
        .ok()
        .and_then(|pid| pid.parse::<u32>().ok())
        == Some(std::process::id());
    if !for_us {
        return Vec::new();
    }
    let count = std::env::var("LISTEN_FDS")
        .ok()
        .and_then(|count| count.parse::<usize>().ok())
        .unwrap_or(0);
    if count > MAX_SYSTEMD_FDS {
        warn!(
            count,
            "systemd passed more sockets than goethite stores; ignoring them"
        );
        return Vec::new();
    }
    let names = std::env::var("LISTEN_FDNAMES").unwrap_or_default();
    let mut names = names.split(':');
    let mut taken = Vec::with_capacity(count);
    for raw in (FIRST..).take(count) {
        // SAFETY: systemd passes exactly LISTEN_FDS open descriptors,
        // numbered from 3, to the process LISTEN_PID names, which was
        // checked above to be this one. This runs before goethite opens any
        // file, so nothing else has closed or reused these numbers, and
        // each number is taken here exactly once.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // Never leak them into another program: an upgrade hands them over
        // explicitly.
        if let Err(err) = rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC) {
            warn!(%err, "cannot mark a socket from systemd close-on-exec");
        }
        taken.push((names.next().unwrap_or_default().to_owned(), fd));
    }
    taken
}

/// systemd is Linux only.
#[cfg(not(target_os = "linux"))]
pub fn take_systemd_fds() -> Vec<(String, OwnedFd)> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn udp() -> (OwnedFd, SocketAddr) {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        (OwnedFd::from(socket), addr)
    }

    #[test]
    fn sockets_handed_over_are_checked() {
        let (fd, addr) = udp();
        let fd = checked(fd, Type::DGRAM, addr).unwrap();
        // Port 0 in the config file accepts any port on the address.
        let fd = checked(fd, Type::DGRAM, "127.0.0.1:0".parse().unwrap()).unwrap();
        assert!(checked(fd, Type::STREAM, addr).is_err(), "the wrong kind");
        let (fd, _) = udp();
        assert!(
            checked(fd, Type::DGRAM, "127.0.0.2:53".parse().unwrap()).is_err(),
            "the wrong address"
        );
        let file = std::fs::File::open("Cargo.toml").unwrap();
        assert!(
            checked(OwnedFd::from(file), Type::DGRAM, addr).is_err(),
            "not a socket"
        );
    }

    #[test]
    fn a_missing_socket_is_named() {
        let config: Config = toml::from_str(
            "[server]\nlisten = \"127.0.0.1:0\"\n[[upstream]]\naddress = \"192.0.2.1\"\n\
             [api]\nenabled = false\n",
        )
        .unwrap();
        let (fd, _) = udp();
        let err = Sockets::adopt(&config, vec![("dns-udp-0-0".into(), fd)])
            .err()
            .unwrap();
        assert!(format!("{err:#}").contains("dns-tcp-0"), "{err:#}");
    }

    #[test]
    fn encrypted_listeners_are_named_and_taken_back() {
        let config: Config = toml::from_str(
            "[server]\nlisten = \"127.0.0.1:0\"\nudp_sockets = 1\n\
             [server.tls]\ncert = \"c\"\nkey = \"k\"\n\
             dot = \"127.0.0.1:0\"\ndoh = [\"127.0.0.1:0\", \"127.0.0.1:0\"]\n\
             [[upstream]]\naddress = \"192.0.2.1\"\n[api]\nenabled = false\n",
        )
        .unwrap();
        let bound = Sockets::bind(&config).unwrap();
        let names: Vec<&str> = bound.named().map(|(name, _)| name).collect();
        assert_eq!(
            names,
            [
                "dns-udp-0-0",
                "dns-tcp-0",
                "dns-dot-0",
                "dns-doh-0",
                "dns-doh-1"
            ]
        );
        let given = bound
            .named()
            .map(|(name, fd)| (name.to_owned(), fd.try_clone_to_owned().unwrap()))
            .collect();
        let mut adopted = Sockets::adopt(&config, given).unwrap();
        let dns = adopted.take_dns().unwrap();
        assert_eq!((dns.dot().len(), dns.doh().len()), (1, 2));

        // A DNS over HTTPS listener gone missing needs a restart.
        let given = bound
            .named()
            .filter(|(name, _)| *name != "dns-doh-1")
            .map(|(name, fd)| (name.to_owned(), fd.try_clone_to_owned().unwrap()))
            .collect();
        let err = Sockets::adopt(&config, given).err().unwrap();
        assert!(format!("{err:#}").contains("dns-doh-1"), "{err:#}");
    }
}
