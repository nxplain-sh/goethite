//! The floating IP: VRRP version 3 (RFC 5798) between the two nodes.
//!
//! Clients use one address for DNS, the floating IP, and whichever node is
//! healthy holds it. Each node runs `goethite vrrp` beside its DNS server:
//! a small process that checks the DNS server, advertises over VRRP and
//! adds or removes the address. It needs `CAP_NET_RAW` (VRRP and ARP go
//! over raw sockets) and `CAP_NET_ADMIN` (changing the interface's
//! addresses), which the DNS server never gets.
//!
//! The pieces:
//!
//! - [`packet`] reads and writes advertisements;
//! - [`machine`] is the state machine, without I/O;
//! - [`netlink`] adds and removes the address;
//! - [`arp`] announces the address after taking it over;
//! - `Vrrp` (Linux only) runs it all.
//!
//! VRRP has no authentication. Advertisements are accepted only from the
//! configured peer, with a TTL of 255 (so from the same link), for the
//! configured address. Anyone on the link can still forge them, as they
//! can forge ARP: the floating IP is as safe as the network segment it is
//! on.

pub mod arp;
pub mod machine;
pub mod netlink;
pub mod packet;
#[cfg(target_os = "linux")]
mod run;

use std::io;
use std::net::Ipv4Addr;

pub use machine::{Heard, State};
#[cfg(target_os = "linux")]
pub use run::Vrrp;

use packet::{GROUP, Received, TTL};

/// How the floating IP is run on this node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VrrpConfig {
    /// The network interface the address lives on, such as `eth0`.
    pub interface: String,
    /// The floating IP.
    pub address: Ipv4Addr,
    /// The virtual router's ID: the same on both nodes, and not used by
    /// another VRRP pair on the network.
    pub router_id: u8,
    /// This node's priority, 1 to 254.
    pub priority: u8,
    /// How often the master advertises, in centiseconds, 1 to 4095.
    pub interval: u16,
    /// Whether to take the address from a peer of lower priority.
    pub preempt: bool,
    /// The peer's address on the interface: advertisements from anyone
    /// else are ignored.
    pub peer: Ipv4Addr,
    /// Advertise to the peer directly instead of to the multicast group,
    /// for networks that drop multicast.
    pub unicast: bool,
}

/// Why a valid advertisement is ignored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Ignored {
    /// For another virtual router on the network: normal.
    #[error("for another virtual router")]
    OtherRouter,
    /// Sent by this node.
    #[error("sent by this node")]
    Own,
    /// Came through a router, or was forged off the link.
    #[error("arrived with TTL {0}, not 255: not from this network")]
    Forwarded(u8),
    /// From a host other than the peer.
    #[error("sent by {0}, which is not the configured peer")]
    Stranger(Ipv4Addr),
    /// Sent to another address than the group or this node.
    #[error("sent to {0}")]
    Misdirected(Ipv4Addr),
    /// For other addresses than the floating IP: the nodes disagree.
    #[error("for other addresses than the floating IP: check [vrrp] on both nodes")]
    OtherAddresses,
    /// An interval of zero.
    #[error("with an interval of zero")]
    NoInterval,
}

/// Checks a received advertisement against the configuration: what RFC
/// 5798 (section 7.1) leaves to the receiver, and that it comes from the
/// peer. `own` is this node's address on the interface.
///
/// # Errors
///
/// [`Ignored`], saying why it is ignored.
pub fn check(
    config: &VrrpConfig,
    own: Ipv4Addr,
    received: &Received<'_>,
) -> Result<Heard, Ignored> {
    let advert = &received.advert;
    if advert.router_id != config.router_id {
        return Err(Ignored::OtherRouter);
    }
    if received.source == own {
        return Err(Ignored::Own);
    }
    if received.ttl != TTL {
        return Err(Ignored::Forwarded(received.ttl));
    }
    if received.source != config.peer {
        return Err(Ignored::Stranger(received.source));
    }
    if received.destination != GROUP && received.destination != own {
        return Err(Ignored::Misdirected(received.destination));
    }
    if !advert.addresses().eq([config.address]) {
        return Err(Ignored::OtherAddresses);
    }
    if advert.interval == 0 {
        return Err(Ignored::NoInterval);
    }
    Ok(Heard {
        priority: advert.priority,
        interval: advert.interval,
        source: received.source,
    })
}

/// Why the floating IP cannot be run.
#[derive(Debug, thiserror::Error)]
pub enum VrrpError {
    /// A system call failed.
    #[error("{what}: {source}")]
    Io {
        /// What was being done.
        what: String,
        /// The error.
        #[source]
        source: io::Error,
    },
    /// Not on Linux.
    #[error("the floating IP (goethite vrrp) needs Linux")]
    Unsupported,
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, reason = "test arithmetic")]
mod tests {
    use super::*;

    const ME: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);
    const PEER: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 11);
    const FLOATING: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 53);

    fn config() -> VrrpConfig {
        VrrpConfig {
            interface: "eth0".into(),
            address: FLOATING,
            router_id: 53,
            priority: 100,
            interval: 100,
            preempt: true,
            peer: PEER,
            unicast: false,
        }
    }

    /// An advertisement as received, with `change` applied to its fields.
    fn heard(
        change: impl FnOnce(&mut (u8, u16, Vec<Ipv4Addr>, Ipv4Addr, Ipv4Addr, u8)),
    ) -> Result<Heard, Ignored> {
        let mut fields = (53, 100, vec![FLOATING], PEER, GROUP, TTL);
        change(&mut fields);
        let (router_id, interval, addresses, source, destination, ttl) = fields;
        let vrrp = packet::encode(router_id, 150, interval, &addresses, source, destination);
        let total = u16::try_from(20 + vrrp.len()).unwrap();
        let mut ip = vec![0x45, 0];
        ip.extend_from_slice(&total.to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0, ttl, packet::PROTOCOL, 0, 0]);
        ip.extend_from_slice(&source.octets());
        ip.extend_from_slice(&destination.octets());
        ip.extend_from_slice(&vrrp);
        check(&config(), ME, &packet::parse(&ip).unwrap())
    }

    #[test]
    fn accepts_the_peer() {
        assert_eq!(
            heard(|_| {}),
            Ok(Heard {
                priority: 150,
                interval: 100,
                source: PEER
            })
        );
        // Unicast, straight to this node.
        assert!(heard(|f| f.4 = ME).is_ok());
    }

    #[test]
    fn ignores_the_rest() {
        assert_eq!(heard(|f| f.0 = 54), Err(Ignored::OtherRouter));
        assert_eq!(heard(|f| f.3 = ME), Err(Ignored::Own));
        assert_eq!(heard(|f| f.5 = 254), Err(Ignored::Forwarded(254)));
        let stranger = Ipv4Addr::new(192, 168, 1, 66);
        assert_eq!(heard(|f| f.3 = stranger), Err(Ignored::Stranger(stranger)));
        let elsewhere = Ipv4Addr::new(192, 168, 1, 12);
        assert_eq!(
            heard(|f| f.4 = elsewhere),
            Err(Ignored::Misdirected(elsewhere))
        );
        assert_eq!(heard(|f| f.2 = vec![]), Err(Ignored::OtherAddresses));
        assert_eq!(
            heard(|f| f.2 = vec![FLOATING, PEER]),
            Err(Ignored::OtherAddresses)
        );
        assert_eq!(heard(|f| f.2 = vec![PEER]), Err(Ignored::OtherAddresses));
        assert_eq!(heard(|f| f.1 = 0), Err(Ignored::NoInterval));
    }
}
